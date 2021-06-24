#include "envoy/config/core/v3/http_uri.pb.h"

#include "source/common/http/message_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/filters/http/common/jwks_fetcher.h"

#include "test/extensions/filters/http/common/mock.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

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
    mock_factory_ctx_.cluster_manager_.initializeThreadLocalClusters({"pubkey_cluster"});
    fetcher_ = JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_,
                                   mock_factory_ctx_.dispatcher_);
    EXPECT_TRUE(fetcher_ != nullptr);
  }

  RemoteJwks remote_jwks_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> mock_factory_ctx_;
  std::unique_ptr<JwksFetcher> fetcher_;
  NiceMock<Tracing::MockSpan> parent_span_;
};

// use this class if the JwksFetcher dispatcher cannot be safely mocked.
// for now, that means the backoff timer will be used.
class JwksFetcherRetryingTest : public testing::Test {
public:
  void setupFetcher(const std::string& config_str) {
    TestUtility::loadFromYaml(config_str, remote_jwks_);
    mock_factory_ctx_.cluster_manager_.initializeThreadLocalClusters({"pubkey_cluster"});
  }

  RemoteJwks remote_jwks_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> mock_factory_ctx_;
  NiceMock<Tracing::MockSpan> parent_span_;
};

// Test findByIssuer
TEST_F(JwksFetcherTest, TestGetSuccess) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  MockJwksReceiver receiver;
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_));
  EXPECT_CALL(receiver, onJwksError(testing::_)).Times(0);

  // Act
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGet400) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "400", "invalid");
  MockJwksReceiver receiver;
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGetNoBody) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", "");
  MockJwksReceiver receiver;
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestGetInvalidJwks) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", "invalid");
  MockJwksReceiver receiver;
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::InvalidJwks));

  // Act
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestHttpFailure) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_,
                           Http::AsyncClient::FailureReason::Reset);
  MockJwksReceiver receiver;
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherTest, TestCancel) {
  // Setup
  setupFetcher(config);
  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, &request);
  MockJwksReceiver receiver;
  EXPECT_CALL(request, cancel());
  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(testing::_)).Times(0);

  // Act
  fetcher_->fetch(parent_span_, receiver);
  // Proper cancel
  fetcher_->cancel();
  // Re-entrant cancel
  fetcher_->cancel();
}

TEST_F(JwksFetcherTest, TestSpanPassedDown) {
  // Setup
  setupFetcher(config);
  MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "200", publicKey);
  NiceMock<MockJwksReceiver> receiver;
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
  fetcher_->fetch(parent_span_, receiver);
}

TEST_F(JwksFetcherRetryingTest, TestRetryOnceThenSucceed) {
  const char retry[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      retry_policy:
        retry_back_off:
          base_interval: 10s
          max_interval: 120s
        num_retries: 3
   )";

  // Setup
  setupFetcher(retry);
  MockDelayedActionUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_);
  MockJwksReceiver receiver;

  Event::MockDispatcher dispatcher;
  Event::MockTimer* retry_timer;
  Event::TimerCb retry_timer_cb;

  EXPECT_CALL(dispatcher, createTimer_(_))
      .WillRepeatedly(Invoke([&retry_timer, &retry_timer_cb](Event::TimerCb timer_cb) {
        retry_timer = new Event::MockTimer();
        retry_timer_cb = timer_cb;
        EXPECT_CALL(*retry_timer, enableTimer(_, _)).WillRepeatedly(Invoke([&retry_timer_cb]() {
          retry_timer_cb();
        }));
        return retry_timer;
      }));

  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, dispatcher));

  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));

  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_));
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network))
      .Times(0); // only called if retries failed.

  // Act
  fetcher->fetch(parent_span_, receiver);

  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 1);
  mock_pubkey.asyn_cb_vector_[0]->onFailure(request, Http::AsyncClient::FailureReason::Reset);

  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 2);

  Http::ResponseMessagePtr response_message(new Http::ResponseMessageImpl(
      Http::ResponseHeaderMapPtr{new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));

  response_message->body().add(publicKey);
  mock_pubkey.asyn_cb_vector_[1]->onSuccess(request, std::move(response_message));
}

TEST_F(JwksFetcherRetryingTest, TestExhaustAllRetriesAndStillFail) {
  const char retry[] = R"(
      http_uri:
        uri: https://pubkey_server/pubkey_path
        cluster: pubkey_cluster

      retry_policy:
        retry_back_off:
          base_interval: 10s
          max_interval: 120s
        num_retries: 3
   )";
  // Setup
  setupFetcher(retry);

  MockDelayedActionUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_);
  MockJwksReceiver receiver;
  Event::MockDispatcher dispatcher;
  Event::MockTimer* retry_timer;
  Event::TimerCb retry_timer_cb;

  EXPECT_CALL(dispatcher, createTimer_(_))
      .WillRepeatedly(Invoke([&retry_timer, &retry_timer_cb](Event::TimerCb timer_cb) {
        retry_timer = new Event::MockTimer();
        retry_timer_cb = timer_cb;
        EXPECT_CALL(*retry_timer, enableTimer(_, _)).WillRepeatedly(Invoke([&retry_timer_cb]() {
          retry_timer_cb();
        }));
        return retry_timer;
      }));

  std::unique_ptr<JwksFetcher> fetcher(
      JwksFetcher::create(mock_factory_ctx_.cluster_manager_, remote_jwks_, dispatcher));

  Http::MockAsyncClientRequest request(
      &(mock_factory_ctx_.cluster_manager_.thread_local_cluster_.async_client_));

  EXPECT_CALL(receiver, onJwksSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwksError(JwksFetcher::JwksReceiver::Failure::Network));

  // Act
  fetcher->fetch(parent_span_, receiver);

  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 1);
  // this does not use the same request as the mock...
  mock_pubkey.asyn_cb_vector_[0]->onFailure(request, Http::AsyncClient::FailureReason::Reset);
  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 2);
  // this does not use the same request as the mock...
  mock_pubkey.asyn_cb_vector_[1]->onFailure(request, Http::AsyncClient::FailureReason::Reset);
  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 3);
  // this does not use the same request as the mock...
  mock_pubkey.asyn_cb_vector_[2]->onFailure(request, Http::AsyncClient::FailureReason::Reset);
  EXPECT_EQ(mock_pubkey.asyn_cb_vector_.size(), 4);
  // this does not use the same request as the mock...
  mock_pubkey.asyn_cb_vector_[3]->onFailure(request, Http::AsyncClient::FailureReason::Reset);
}
} // namespace
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
