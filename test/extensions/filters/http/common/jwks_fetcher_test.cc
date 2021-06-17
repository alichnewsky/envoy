#include "envoy/config/core/v3/http_uri.pb.h"

#include "source/common/http/message_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/common/jwks_fetcher.h"

#include "test/extensions/filters/http/common/mock.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

using envoy::config::core::v3::HttpUri;
using envoy::extensions::filters::http::jwt_authn::v3::RemoteJwks;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {

const char publicKey[] = R"(
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "62a93512c9ee4c7f8067b5a216dade2763d32a47",
      "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "b3319a147514df7ee5e4bcdee51350cc890cc89e",
      "n": "up97uqrF9MWOPaPkwSaBeuAPLOr9FKcaWGdVEGzQ4f3Zq5WKVZowx9TCBxmImNJ1qmUi13pB8otwM_l5lfY1AFBMxVbQCUXntLovhDaiSvYp4wGDjFzQiYA-pUq8h6MUZBnhleYrkU7XlCBwNVyN8qNMkpLA7KFZYz-486GnV2NIJJx_4BGa3HdKwQGxi2tjuQsQvao5W4xmSVaaEWopBwMy2QmlhSFQuPUpTaywTqUcUq_6SfAHhZ4IDa_FxEd2c2z8gFGtfst9cY3lRYf-c_ZdboY3mqN9Su3-j3z5r2SHWlhB_LNAjyWlBGsvbGPlTqDziYQwZN4aGsqVKQb9Vw",
      "e": "AQAB"
    }
  ]
}
)";

const std::string config = R"(
http_uri:
  uri: https://pubkey_server/pubkey_path
  cluster: pubkey_cluster
  timeout:
    seconds: 5
)";

class JwksFetcherTest : public testing::Test {
public:
  void setupFetcher(const std::string& config_str) {
    TestUtility::loadFromYaml(config_str, remote_jwks_);
    uri_ = remote_jwks_.http_uri();
    mock_factory_ctx_.cluster_manager_.initializeThreadLocalClusters({"pubkey_cluster"});
  }

  RemoteJwks remote_jwks_;
  HttpUri uri_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> mock_factory_ctx_;
  NiceMock<Tracing::MockSpan> parent_span_;
};

// Test findByIssuer
TEST_F(JwksFetcherTest, TestGetSuccess) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_));
  EXPECT_CALL(receiver, onJwksError(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGet400) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "400", "invalid");
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGetNoBody) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", "");
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGetInvalidJwks) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", "invalid");
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::InvalidJwks));

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestHttpFailure) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_,
                           Http::AsyncClient::FailureReason::Reset);
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestCancel) {
  // Setup
  setupFetcher(config);
  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, &request);
  MockJwksReceiver receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(request, cancel());
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
  // Proper cancel
  fetcher->cancel();
  // Re-entrant cancel
  fetcher->cancel();
}

TEST_F(JwksFetcherTest, TestSpanPassedDown) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  NiceMock<MockJwksReceiver> receiver;
  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, mock_factory_ctx_.dispatcher_));

  // Expectations for span
  EXPECT_CALL(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_,
              send_(_, _, _))
      .WillOnce(Invoke(
          [this](Http::RequestMessagePtr&, Http::AsyncClient::Callbacks&,
                 const Http::AsyncClient::RequestOptions& options) -> Http::AsyncClient::Request* {
            EXPECT_TRUE(options.parent_span_ == &this->parent_span_);
            EXPECT_TRUE(options.child_span_name_ == "JWT Remote PubKey Fetch");
            return nullptr;
          }));

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);
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

TEST_F(JwksFetcherTest, TestRetryOnceThenSucceed) {
  const char retry[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      retry_policy:
        retry_back_off:
          base_interval: 0.001s
          max_interval: 0.1s
        num_retries: 3
   )";

  // Setup
  setupFetcher(retry);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  MockJwksReceiver receiver;

  Event::MockDispatcher dispatcher;
  Event::MockTimer* retry_timer;
  Event::TimerCb retry_timer_cb;

  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, dispatcher));

  EXPECT_CALL(dispatcher, createTimer_(_)).WillRepeatedly(Invoke([&retry_timer, &retry_timer_cb](Event::TimerCb timer_cb) {
    retry_timer = new Event::MockTimer();
    retry_timer_cb = timer_cb;
    EXPECT_CALL(*retry_timer, enableTimer(_,_)).WillRepeatedly(Invoke([&retry_timer_cb]() { retry_timer_cb();} ));
    return retry_timer;
  }));



  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));

  int numFailures = 0;
  int numSuccesses = 0;

  EXPECT_CALL(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_,
              send_(_, _, _))
      .WillOnce(
          Invoke([&request, &numFailures](
                     Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& cb,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            cb.onFailure(request, Http::AsyncClient::FailureReason::Reset);
            ++numFailures;
            return &request;
          }))
      .WillOnce(Invoke([&request, &numSuccesses](Http::RequestMessagePtr&,
                                                 Http::AsyncClient::Callbacks& cb,
                                                 const Http::AsyncClient::RequestOptions&)
                           -> Http::AsyncClient::Request* {
        Http::ResponseMessagePtr response_message(new Http::ResponseMessageImpl(
            Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));

        response_message->body().add(jwks_text);
        cb.onSuccess(request, std::move(response_message));
        ++numSuccesses;
        return &request;
      }));

  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(1);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network)).Times(0); // only called if retries failed.

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);

  EXPECT_EQ(numSuccesses, 1);
  EXPECT_EQ(numFailures, 1);
}

TEST_F(JwksFetcherTest, TestExhaustAllRetriesAndStillFail) {
  const char retry[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      retry_policy:
        retry_back_off:
          base_interval: 0.001s
          max_interval: 0.1s
        num_retries: 3
   )";
  // Setup
  setupFetcher(retry);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  MockJwksReceiver receiver;
  Event::MockDispatcher dispatcher;
  Event::MockTimer* retry_timer;
  Event::TimerCb retry_timer_cb;

  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, dispatcher));

  EXPECT_CALL(dispatcher, createTimer_(_)).WillRepeatedly(Invoke([&retry_timer, &retry_timer_cb](Event::TimerCb timer_cb) {
    retry_timer = new Event::MockTimer();
    retry_timer_cb = timer_cb;
    EXPECT_CALL(*retry_timer, enableTimer(_,_)).WillRepeatedly(Invoke([&retry_timer_cb]() { retry_timer_cb();} ));
    return retry_timer;
  }));

  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));

  int numFailures = 0;
  int numSuccesses = 0;

  EXPECT_CALL(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_,
              send_(_, _, _))
      .WillRepeatedly(
          Invoke([&request, &numFailures](
                     Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& cb,
                     const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
            cb.onFailure(request, Http::AsyncClient::FailureReason::Reset);
            ++numFailures;
            return &request;
          }));

  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network)).Times(1);

  // Act
  fetcher->fetch(uri_, parent_span_, receiver);

  EXPECT_EQ(numSuccesses, 0);
  EXPECT_EQ(numFailures, 4);
}
} // namespace
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
