#include "source/extensions/filters/http/common/jwks_fetcher.h"

#include "envoy/config/core/v3/http_uri.pb.h"

#include "source/common/common/backoff_strategy.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/logger.h"
#include "source/common/common/random_generator.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"

#include "absl/time/time.h"
#include "jwt_verify_lib/status.h"

using envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {
// Parameters of the jittered backoff strategy.
static constexpr uint32_t RetryInitialDelayMilliseconds = 1000;
static constexpr uint32_t RetryMaxDelayMilliseconds = 10 * 1000;
static constexpr uint32_t RetryCount = 0;

class JwksFetcherImpl : public JwksFetcher,
                        public Logger::Loggable<Logger::Id::filter>,
                        public Http::AsyncClient::Callbacks {
public:
  JwksFetcherImpl(Upstream::ClusterManager& cm, const RemoteJwks& remote_jwks)
      : cm_(cm), remote_jwks_(remote_jwks), num_retries_(RetryCount),
        retries_remaining_(RetryCount) {
    ENVOY_LOG(trace, "{}", __func__);

    uint64_t base_interval_ms = RetryInitialDelayMilliseconds;
    uint64_t max_interval_ms = RetryMaxDelayMilliseconds;

    if (remote_jwks_.has_retry_policy()) {
      if (remote_jwks_.retry_policy().has_retry_back_off()) {
        base_interval_ms =
            PROTOBUF_GET_MS_REQUIRED(remote_jwks_.retry_policy().retry_back_off(), base_interval);

        max_interval_ms = PROTOBUF_GET_MS_OR_DEFAULT(remote_jwks_.retry_policy().retry_back_off(),
                                                     max_interval, base_interval_ms * 10);
        if (max_interval_ms < base_interval_ms) {
          throw EnvoyException("max_interval must be greater than or equal to the base_interval");
        }
      }

      num_retries_ = PROTOBUF_GET_WRAPPED_OR_DEFAULT(remote_jwks_.retry_policy(), num_retries, 1);
    }

    backoff_strategy_ = std::make_unique<Envoy::JitteredExponentialBackOffStrategy>(
        base_interval_ms, max_interval_ms, random_);

    retries_remaining_ = num_retries_;
  }

  ~JwksFetcherImpl() override { cancel(); }

  void cancel() final {
    if (request_ && !complete_) {
      request_->cancel();
      ENVOY_LOG(debug, "fetch pubkey [uri = {}]: canceled", uri_->uri());
    }
    reset();
  }

  void fetch(const envoy::config::core::v3::HttpUri& uri, Tracing::Span& parent_span,
             JwksFetcher::JwksReceiver& receiver) override {
    ENVOY_LOG(trace, "{}", __func__);
    ASSERT(!receiver_);

    complete_ = false;
    receiver_ = &receiver;
    uri_ = &uri;
    parent_span_ = &parent_span;

    // Check if cluster is configured, fail the request if not.
    const auto thread_local_cluster = cm_.getThreadLocalCluster(uri.cluster());
    if (thread_local_cluster == nullptr) {
      ENVOY_LOG(error, "{}: fetch pubkey [uri = {}] failed: [cluster = {}] is not configured",
                __func__, uri.uri(), uri.cluster());
      complete_ = true;
      receiver_->onJwksError(JwksFetcher::JwksReceiver::Failure::Network);
      reset();
      return;
    }

    Http::RequestMessagePtr message = Http::Utility::prepareHeaders(uri);
    message->headers().setReferenceMethod(Http::Headers::get().MethodValues.Get);
    ENVOY_LOG(debug, "fetch pubkey from [uri = {}]: start", uri_->uri());
    auto options = Http::AsyncClient::RequestOptions()
                       .setTimeout(std::chrono::milliseconds(
                           DurationUtil::durationToMilliseconds(uri.timeout())))
                       .setParentSpan(parent_span)
                       .setChildSpanName("JWT Remote PubKey Fetch");
    request_ = thread_local_cluster->httpAsyncClient().send(std::move(message), *this, options);
  }

  // HTTP async receive methods
  void onSuccess(const Http::AsyncClient::Request&, Http::ResponseMessagePtr&& response) override {
    ENVOY_LOG(trace, "{}", __func__);
    complete_ = true;
    const uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
    if (status_code == enumToInt(Http::Code::OK)) {
      ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: success", __func__, uri_->uri());
      if (response->body().length() != 0) {
        const auto body = response->bodyAsString();
        auto jwks =
            google::jwt_verify::Jwks::createFrom(body, google::jwt_verify::Jwks::Type::JWKS);
        if (jwks->getStatus() == google::jwt_verify::Status::Ok) {
          ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: succeeded", __func__, uri_->uri());
          receiver_->onJwksSuccess(std::move(jwks));
          reset();
          return;
        } else {
          ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: invalid jwks", __func__, uri_->uri());
          receiver_->onJwksError(JwksFetcher::JwksReceiver::Failure::InvalidJwks);
        }
      } else {
        ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: body is empty", __func__, uri_->uri());
        receiver_->onJwksError(JwksFetcher::JwksReceiver::Failure::Network);
      }
    } else {
      ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: response status code {}", __func__,
                uri_->uri(), status_code);
      receiver_->onJwksError(JwksFetcher::JwksReceiver::Failure::Network);
    }
    retryFetch();
  }

  void onFailure(const Http::AsyncClient::Request&,
                 Http::AsyncClient::FailureReason reason) override {
    ENVOY_LOG(debug, "{}: fetch pubkey [uri = {}]: network error {}", __func__, uri_->uri(),
              enumToInt(reason));
    complete_ = true;
    receiver_->onJwksError(JwksFetcher::JwksReceiver::Failure::Network);
    retryFetch();
  }

  void onBeforeFinalizeUpstreamSpan(Tracing::Span&, const Http::ResponseHeaderMap*) override {}

private:
  Upstream::ClusterManager& cm_;
  bool complete_{};
  JwksFetcher::JwksReceiver* receiver_{};
  const envoy::config::core::v3::HttpUri* uri_{};

  Http::AsyncClient::Request* request_{};

  Tracing::Span* parent_span_{};

  const envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks& remote_jwks_;

  Envoy::BackOffStrategyPtr backoff_strategy_;

  uint32_t num_retries_;

  uint32_t retries_remaining_;

  Envoy::Random::RandomGeneratorImpl random_;

  void reset() {
    request_ = nullptr;
    receiver_ = nullptr;
    uri_ = nullptr;
    parent_span_ = nullptr;

    // truncated backoff back to 0 retries attempted.
    retries_remaining_ = num_retries_;

    if (backoff_strategy_) {
      // backoff strategy : back to initial (small) delay
      backoff_strategy_->reset();
    }
  }

  void retryFetch() {

    // cant' fetch() if receiver isn't null... ( for example after a reset() )
    auto* receiver = receiver_;
    receiver_ = nullptr;

    if (backoff_strategy_) {
      if (retries_remaining_-- > 0) {

        auto retry_ms = std::chrono::milliseconds(backoff_strategy_->nextBackOffMs());

        ENVOY_LOG(warn, "retrying after {} milliseconds backoff", retry_ms.count());

        absl::SleepFor(absl::FromChrono(retry_ms));

        fetch(*uri_, *parent_span_, *receiver);

      } else {
        ENVOY_LOG(warn, "not retrying anymore");
        reset();
      }
    } else {
      ENVOY_LOG(warn, "not retrying at all");
      reset();
    }
  }
};
} // namespace

JwksFetcherPtr JwksFetcher::create(
    Upstream::ClusterManager& cm,
    const envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks& remote_jwks) {
  return std::make_unique<JwksFetcherImpl>(cm, remote_jwks);
}
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
