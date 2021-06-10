#include "source/extensions/filters/http/jwt_authn/jwks_async_fetcher.h"

#include "source/common/protobuf/utility.h"
#include "source/common/tracing/http_tracer_impl.h"

using envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {
namespace {

// Default cache expiration time in 5 minutes.
constexpr int PubkeyCacheExpirationSec = 600;

// Parameters of the jittered backoff strategy.
static constexpr uint32_t RetryInitialDelayMilliseconds = 1000;
static constexpr uint32_t RetryMaxDelayMilliseconds = 10 * 1000;
static constexpr uint32_t RetryCount = 0;

} // namespace

JwksAsyncFetcher::JwksAsyncFetcher(const RemoteJwks& remote_jwks,
                                   Server::Configuration::FactoryContext& context,
                                   CreateJwksFetcherCb create_fetcher_fn,
                                   JwtAuthnFilterStats& stats, JwksDoneFetched done_fn)
    : remote_jwks_(remote_jwks), context_(context), create_fetcher_fn_(create_fetcher_fn),
      stats_(stats), done_fn_(done_fn), cache_duration_(getCacheDuration(remote_jwks)),
      debug_name_(absl::StrCat("Jwks async fetching url=", remote_jwks_.http_uri().uri())),
      num_retries_(RetryCount) {

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

    retry_timer_ = context_.dispatcher().createTimer([this]() -> void { fetch(); });
  }

  backoff_strategy_ = std::make_unique<Envoy::JitteredExponentialBackOffStrategy>(
      base_interval_ms, max_interval_ms, random_);

  retries_remaining_ = num_retries_;

  // if async_fetch is not enabled, do nothing.
  if (!remote_jwks_.has_async_fetch()) {
    return;
  }

  cache_duration_timer_ = context_.dispatcher().createTimer([this]() -> void { fetch(); });

  // For fast_listener, just trigger a fetch, not register with init_manager.
  if (remote_jwks_.async_fetch().fast_listener()) {
    fetch();
    return;
  }

  // Register to init_manager, force the listener to wait for the fetching.
  init_target_ = std::make_unique<Init::TargetImpl>(debug_name_, [this]() -> void { fetch(); });
  context_.initManager().add(*init_target_);
}

std::chrono::seconds JwksAsyncFetcher::getCacheDuration(const RemoteJwks& remote_jwks) {
  if (remote_jwks.has_cache_duration()) {
    return std::chrono::seconds(DurationUtil::durationToSeconds(remote_jwks.cache_duration()));
  }
  return std::chrono::seconds(PubkeyCacheExpirationSec);
}

void JwksAsyncFetcher::fetch() {
  if (fetcher_) {
    fetcher_->cancel();
  }

  ENVOY_LOG(debug, "{}: started", debug_name_);
  fetcher_ = create_fetcher_fn_(context_.clusterManager());
  fetcher_->fetch(remote_jwks_.http_uri(), Tracing::NullSpan::instance(), *this);
}

void JwksAsyncFetcher::handleFetchDone() {
  if (init_target_) {
    init_target_->ready();
    init_target_.reset();
  }

  if (backoff_strategy_) {
    backoff_strategy_->reset();
  }
  retries_remaining_ = num_retries_;

  cache_duration_timer_->enableTimer(cache_duration_);
}

void JwksAsyncFetcher::onJwksSuccess(google::jwt_verify::JwksPtr&& jwks) {
  stats_.jwks_fetch_success_.inc();

  done_fn_(std::move(jwks));
  handleFetchDone();

  // Note: not to free fetcher_ within onJwksSuccess or onJwksError function.
  // They are passed to fetcher_->fetch() and are called by fetcher_ after fetch is done.
  // After calling these callback functions, fetch_ calls its reset() function.
  // If fetcher_ is freed by the callback,  calling reset() will crash.

  // Not need to free fetcher_. At the next fetch(), it will be freed with a cancel() call.
  // The cancel() is needed to cancel the old call before the new one is created.
  // But it is a no-op if the call is completed.
}

void JwksAsyncFetcher::onJwksError(Failure) {
  stats_.jwks_fetch_failed_.inc();

  ENVOY_LOG(warn, "{}: failed", debug_name_);

  // are all failure reasons a valid reason to retry fetching ?
  if (backoff_strategy_) {
    if (retries_remaining_-- > 0) {

      auto retry_ms = std::chrono::milliseconds(backoff_strategy_->nextBackOffMs());

      ENVOY_LOG(warn, "{}: retrying after {} milliseconds backoff", debug_name_, retry_ms.count());

      retry_timer_->enableTimer(retry_ms);

      return;
    } else {
      ENVOY_LOG(warn, "{}: not retrying {}", debug_name_, num_retries_ > 0 ? "anymore" : "at all");
    }
  }
  handleFetchDone();

  // Note: not to free fetcher_ in this function. Please see comment at onJwksSuccess.
}

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
