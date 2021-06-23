#include "source/extensions/filters/http/jwt_authn/jwks_async_fetcher.h"

#include "test/extensions/filters/http/jwt_authn/test_common.h"
#include "test/extensions/filters/http/common/mock.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"

using envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks;
using Envoy::Extensions::HttpFilters::Common::JwksFetcher;
using Envoy::Extensions::HttpFilters::Common::JwksFetcherPtr;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace JwtAuthn {
namespace {

JwtAuthnFilterStats generateMockStats(Stats::Scope& scope) {
  return {ALL_JWT_AUTHN_FILTER_STATS(POOL_COUNTER_PREFIX(scope, ""))};
}

class MockJwksFetcher : public Common::JwksFetcher {
public:
  using SaveJwksReceiverFn = std::function<void(JwksReceiver& receiver)>;
  MockJwksFetcher(SaveJwksReceiverFn receiver_fn) : receiver_fn_(receiver_fn) {}

  void cancel() override {}
  void fetch(Tracing::Span&, JwksReceiver& receiver) override { receiver_fn_(receiver); }

private:
  SaveJwksReceiverFn receiver_fn_;
};

// TestParam is for fast_listener,
class JwksAsyncFetcherTest : public testing::TestWithParam<bool> {
public:
  JwksAsyncFetcherTest() : stats_(generateMockStats(context_.scope())) {}

  // init manager is used in is_slow_listener mode
  bool initManagerUsed() const {
    return config_.has_async_fetch() && !config_.async_fetch().fast_listener();
  }

  void setupAsyncFetcher(const std::string& config_str) {
    TestUtility::loadFromYaml(config_str, config_);
    if (config_.has_async_fetch()) {
      // Param is for fast_listener,
      if (GetParam()) {
        config_.mutable_async_fetch()->set_fast_listener(true);
      }
    }

    if (initManagerUsed()) {
      EXPECT_CALL(context_.init_manager_, add(_))
          .WillOnce(Invoke([this](const Init::Target& target) {
            init_target_handle_ = target.createHandle("test");
          }));
    }

    // if async_fetch is enabled, timer is created
    if (config_.has_async_fetch()) {
      timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
      expected_duration_ = JwksAsyncFetcher::getCacheDuration(config_);
    }

    if (config_.has_retry_policy()) {
      num_retries_ = PROTOBUF_GET_WRAPPED_OR_DEFAULT(config_.retry_policy(), num_retries, 1);
    }

    async_fetcher_ = std::make_unique<JwksAsyncFetcher>(
        config_, context_,
        [this](Upstream::ClusterManager&, const RemoteJwks&, Event::Dispatcher&) {
          return std::make_unique<MockJwksFetcher>(
              [this](Common::JwksFetcher::JwksReceiver& receiver) {
                fetch_receiver_array_.push_back(&receiver);
              });
        },
        stats_,
        [this](google::jwt_verify::JwksPtr&& jwks) { out_jwks_array_.push_back(std::move(jwks)); });

    if (initManagerUsed()) {
      init_target_handle_->initialize(init_watcher_);
    }
  }

  RemoteJwks config_;
  JwksAsyncFetcherPtr async_fetcher_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  JwtAuthnFilterStats stats_;
  std::vector<Common::JwksFetcher::JwksReceiver*> fetch_receiver_array_;
  std::vector<google::jwt_verify::JwksPtr> out_jwks_array_;

  Init::TargetHandlePtr init_target_handle_;
  NiceMock<Init::ExpectableWatcherImpl> init_watcher_;
  Event::MockTimer* timer_{};
  std::chrono::milliseconds expected_duration_;

  uint32_t num_retries_{0u};
};

INSTANTIATE_TEST_SUITE_P(JwksAsyncFetcherTest, JwksAsyncFetcherTest,
                         testing::ValuesIn({false, true}));

TEST_P(JwksAsyncFetcherTest, TestNotAsyncFetch) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
)";

  setupAsyncFetcher(config);
  // fetch is not called
  EXPECT_EQ(fetch_receiver_array_.size(), 0);
  // Not Jwks output
  EXPECT_EQ(out_jwks_array_.size(), 0);
  // init_watcher ready is not called.
  init_watcher_.expectReady().Times(0);

  EXPECT_EQ(0U, stats_.jwks_fetch_success_.value());
  EXPECT_EQ(0U, stats_.jwks_fetch_failed_.value());
}

TEST_P(JwksAsyncFetcherTest, TestGoodFetch) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
      async_fetch: {}
)";

  setupAsyncFetcher(config);
  // Jwks response is not received yet
  EXPECT_EQ(out_jwks_array_.size(), 0);

  if (initManagerUsed()) {
    // Verify ready is not called.
    init_watcher_.expectReady().Times(0);
    EXPECT_TRUE(::testing::Mock::VerifyAndClearExpectations(&init_watcher_));
    init_watcher_.expectReady();
  }

  // Trigger the Jwks response
  EXPECT_EQ(fetch_receiver_array_.size(), 1);
  auto jwks = google::jwt_verify::Jwks::createFrom(PublicKey, google::jwt_verify::Jwks::JWKS);
  fetch_receiver_array_[0]->onJwksSuccess(std::move(jwks));

  // Output 1 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 1);

  EXPECT_EQ(1U, stats_.jwks_fetch_success_.value());
  EXPECT_EQ(0U, stats_.jwks_fetch_failed_.value());
}

TEST_P(JwksAsyncFetcherTest, TestNetworkFailureFetch) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
      async_fetch: {}
)";

  // Just start the Jwks fetch call
  setupAsyncFetcher(config);
  // Jwks response is not received yet
  EXPECT_EQ(out_jwks_array_.size(), 0);

  if (initManagerUsed()) {
    // Verify ready is not called.
    init_watcher_.expectReady().Times(0);
    EXPECT_TRUE(::testing::Mock::VerifyAndClearExpectations(&init_watcher_));
    // Verify ready is called.
    init_watcher_.expectReady();
  }

  // Trigger the Jwks response
  EXPECT_EQ(fetch_receiver_array_.size(), 1);
  fetch_receiver_array_[0]->onJwksError(Common::JwksFetcher::JwksReceiver::Failure::Network);

  // Output 0 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 0);

  EXPECT_EQ(0U, stats_.jwks_fetch_success_.value());
  EXPECT_EQ(1U, stats_.jwks_fetch_failed_.value());
}

TEST_P(JwksAsyncFetcherTest, TestGoodFetchAndRefresh) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
      async_fetch: {}
)";

  setupAsyncFetcher(config);
  // Initial fetch is successful
  EXPECT_EQ(fetch_receiver_array_.size(), 1);
  auto jwks = google::jwt_verify::Jwks::createFrom(PublicKey, google::jwt_verify::Jwks::JWKS);
  fetch_receiver_array_[0]->onJwksSuccess(std::move(jwks));

  // Output 1 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 1);

  // Expect refresh timer is enabled.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  timer_->invokeCallback();

  // refetch again after cache duration interval: successful.
  EXPECT_EQ(fetch_receiver_array_.size(), 2);
  auto jwks1 = google::jwt_verify::Jwks::createFrom(PublicKey, google::jwt_verify::Jwks::JWKS);
  fetch_receiver_array_[1]->onJwksSuccess(std::move(jwks1));

  // Output 2 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 2);
  EXPECT_EQ(2U, stats_.jwks_fetch_success_.value());
  EXPECT_EQ(0U, stats_.jwks_fetch_failed_.value());
}

TEST_P(JwksAsyncFetcherTest, TestNetworkFailureFetchAndRefresh) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster
      async_fetch: {}
)";

  // Just start the Jwks fetch call
  setupAsyncFetcher(config);
  // first fetch: network failure.
  EXPECT_EQ(fetch_receiver_array_.size(), 1);
  fetch_receiver_array_[0]->onJwksError(Common::JwksFetcher::JwksReceiver::Failure::Network);

  // Output 0 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 0);

  // Expect refresh timer is enabled.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  timer_->invokeCallback();

  // refetch again after cache duration interval: network failure.
  EXPECT_EQ(fetch_receiver_array_.size(), 2);
  fetch_receiver_array_[1]->onJwksError(Common::JwksFetcher::JwksReceiver::Failure::Network);

  // Output 0 jwks.
  EXPECT_EQ(out_jwks_array_.size(), 0);
  EXPECT_EQ(0U, stats_.jwks_fetch_success_.value());
  EXPECT_EQ(2U, stats_.jwks_fetch_failed_.value());
}

const std::string jwks_text = R"(
{
  "keys": [
        {
          "kty": "RSA",
          "alg": "RS256",
          "use": "sig",
          "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
          "n": "0YWnm_eplO9BFtXszMRQNL5UtZ8HJdTH2jK7vjs4XdLkPW7YBkkm_2xNgcaVpkW0VT2l4mU3KftR-6s3Oa5Rnz5BrWEUkCTVVolR7VYksfqIB2I_x5yZHdOiomMTcm3DheUUCgbJRv5OKRnNqszA4xHn3tA3Ry8VO3X7BgKZYAUh9fyZTFLlkeAh0-bLK5zvqCmKW5QgDIXSxUTJxPjZCgfx1vmAfGqaJb-nvmrORXQ6L284c73DUL7mnt6wj3H6tVqPKA27j56N0TB1Hfx4ja6Slr8S4EB3F1luYhATa1PKUSH8mYDW11HolzZmTQpRoLV8ZoHbHEaTfqX_aYahIw",
          "e": "AQAB"
        },
        {
          "kty": "RSA",
          "alg": "RS256",
          "use": "sig",
          "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
          "n": "qDi7Tx4DhNvPQsl1ofxxc2ePQFcs-L0mXYo6TGS64CY_2WmOtvYlcLNZjhuddZVV2X88m0MfwaSA16wE-RiKM9hqo5EY8BPXj57CMiYAyiHuQPp1yayjMgoE1P2jvp4eqF-BTillGJt5W5RuXti9uqfMtCQdagB8EC3MNRuU_KdeLgBy3lS3oo4LOYd-74kRBVZbk2wnmmb7IhP9OoLc1-7-9qU1uhpDxmE6JwBau0mDSwMnYDS4G_ML17dC-ZDtLd1i24STUw39KH0pcSdfFbL2NtEZdNeam1DDdk0iUtJSPZliUHJBI_pj8M-2Mn_oA8jBuI8YKwBqYkZCN1I95Q",
          "e": "AQAB"
       }
    ]
 }
 )";

class JwksAsyncFetcherRetryingTest : public testing::Test,
                                     public Logger::Loggable<Logger::Id::filter> {
public:
  JwksAsyncFetcherRetryingTest() : stats_(generateMockStats(context_.scope())) {}

  void setupAsyncFetcher(const std::string& config_str, uint32_t numFailures = 0,
                         uint32_t numSuccess = 1) {
    TestUtility::loadFromYaml(config_str, config_);

    EXPECT_TRUE(config_.has_async_fetch());
    EXPECT_TRUE(config_.async_fetch().fast_listener());
    EXPECT_TRUE(config_.has_retry_policy());

    timer_ = new NiceMock<Event::MockTimer>();
    expected_duration_ = JwksAsyncFetcher::getCacheDuration(config_);

    retry_timer_ = new NiceMock<Event::MockTimer>();
    num_retries_ = PROTOBUF_GET_WRAPPED_OR_DEFAULT(config_.retry_policy(), num_retries, 1);

    context_.cluster_manager_.initializeThreadLocalClusters({"pubkey_cluster"});
    request_ = std::make_unique<Http::MockAsyncClientRequest>(
        &(context_.cluster_manager_.thread_local_cluster_.async_client_));

    num_expected_failures_ = numFailures;
    num_expected_successes_ = numSuccess;

    if (num_expected_failures_ > 0 || num_expected_successes_ > 0) {

      EXPECT_CALL(context_.cluster_manager_.thread_local_cluster_.async_client_, send_(_, _, _))
          .WillRepeatedly(Invoke(
              [this](Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& cb,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
                if (num_expected_failures_ > num_internal_failures_) {
                  ++num_internal_failures_;
                  cb.onFailure(*request_, Http::AsyncClient::FailureReason::Reset);
                  return request_.get();

                } else if (num_expected_successes_ > num_internal_successes_) {

                  Http::ResponseMessagePtr response_message(
                      new Http::ResponseMessageImpl(Http::ResponseHeaderMapPtr{
                          new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));

                  response_message->body().add(jwks_text);
                  ++num_internal_successes_;
                  cb.onSuccess(*request_, std::move(response_message));
                  return request_.get();
                } else {
                  ++num_unexpected_calls_;
                  return nullptr;
                }
              }));
    }

    EXPECT_CALL(context_.dispatcher_, createTimer_(_))
        .WillOnce(Invoke([this](Event::TimerCb timer_cb) {
          refresh_cache_cb_ = timer_cb;
          ENVOY_LOG(trace, "createTimer() : returning the async timer");
          EXPECT_CALL(*timer_, enableTimer(_, _)).WillOnce(Invoke([]() {
            ENVOY_LOG(trace, "ignoring cache refreshing callback with enableTimer()");
          }));
          return timer_;
        }))
        .WillRepeatedly(Invoke([this](Event::TimerCb timer_cb) {
          retry_timer_cb_ = timer_cb;
          ENVOY_LOG(trace, "createTimer() : returning the retry_timer_");
          EXPECT_CALL(*retry_timer_, enableTimer(_, _)).WillRepeatedly(Invoke([this]() {
            ENVOY_LOG(trace, "invoking retry callback with enableTimer()");
            retry_timer_cb_();
          }));
          return retry_timer_;
        }));

    async_fetcher_ = std::make_unique<JwksAsyncFetcher>(
        config_, context_,
        [this](Upstream::ClusterManager&, const RemoteJwks&, Event::Dispatcher& dispatcher) {
          auto fetcher = JwksFetcher::create(context_.cluster_manager_, config_, dispatcher);
          return fetcher;
        },
        stats_,
        [this](google::jwt_verify::JwksPtr&& jwks) { out_jwks_array_.push_back(std::move(jwks)); });
  }

  RemoteJwks config_;
  JwksAsyncFetcherPtr async_fetcher_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  JwtAuthnFilterStats stats_;
  std::vector<Common::JwksFetcher::JwksReceiver*> fetch_receiver_array_;
  std::vector<google::jwt_verify::JwksPtr> out_jwks_array_;

  Init::TargetHandlePtr init_target_handle_;
  NiceMock<Init::ExpectableWatcherImpl> init_watcher_;

  Event::MockTimer* timer_{};
  std::chrono::milliseconds expected_duration_;
  Event::TimerCb refresh_cache_cb_;

  Event::MockTimer* retry_timer_{};
  uint32_t num_retries_{0u};
  Event::TimerCb retry_timer_cb_;

  std::unique_ptr<Http::MockAsyncClientRequest> request_;
  uint32_t num_expected_successes_{0u};
  uint32_t num_expected_failures_{0u};
  uint32_t num_internal_successes_{0u};
  uint32_t num_internal_failures_{0u};
  uint32_t num_unexpected_calls_{0u};
};

TEST_F(JwksAsyncFetcherRetryingTest, TestNetworkFailureFetchAndRetrySuccessfully) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      async_fetch:
        fast_listener: true

      retry_policy:
        retry_back_off:
          base_interval: 10s
          max_interval: 120s
        num_retries: 3
)";

  // Just start the Jwks fetch call because there's a fast listener by default.
  setupAsyncFetcher(config, 1, 1);

  EXPECT_EQ(1U, num_internal_failures_);
  EXPECT_EQ(1U, num_internal_successes_);
  EXPECT_EQ(0U, num_unexpected_calls_);
}

TEST_F(JwksAsyncFetcherRetryingTest, TestNetworkFailureFetchAndRetryWithoutSuccess) {
  const char config[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      async_fetch:
        fast_listener: true

      retry_policy:
        retry_back_off:
          base_interval: 10s
          max_interval: 120s
        num_retries: 3
)";

  // Just start the Jwks fetch call because there's a fast listener by default.
  setupAsyncFetcher(config, 4, 0);

  EXPECT_EQ(4U, num_internal_failures_);
  EXPECT_EQ(0U, num_internal_successes_);
  EXPECT_EQ(0U, num_unexpected_calls_);
}

} // namespace
} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
