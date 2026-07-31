from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]
ROOT = SOURCE_DIR.parents[1]
CMAKE = ROOT / "Telegram" / "CMakeLists.txt"
SESSION_DIR = SOURCE_DIR / "mtproto" / "session" / "private"

SESSION_CPP = SOURCE_DIR / "mtproto" / "session" / "session.cpp"
CONNECTION_CPP = SESSION_DIR / "connection.cpp"
TRANSPORT_CPP = SESSION_DIR / "transport.cpp"
TRANSPORT_H = SESSION_DIR / "transport.h"
SESSION_PRIVATE_H = SESSION_DIR / "session_private.h"
AUTH_CPP = SESSION_DIR / "auth.cpp"
SEND_CPP = SESSION_DIR / "send.cpp"
CONNECTION_FACTORY_H = SESSION_DIR / "connection_factory.h"
CONNECTION_FACTORY_CPP = SESSION_DIR / "connection_factory.cpp"
AUTH_FACTORY_H = SESSION_DIR / "auth_factory.h"
AUTH_FACTORY_CPP = SESSION_DIR / "auth_factory.cpp"


def read(path):
    assert path.exists(), f"missing expected source file: {path}"
    return path.read_text(encoding="utf-8")


def test_session_connection_factory_owns_live_connection_creation():
    header = read(CONNECTION_FACTORY_H)
    source = read(CONNECTION_FACTORY_CPP)
    session = read(CONNECTION_CPP)
    private = read(SESSION_PRIVATE_H)
    cmake = read(CMAKE)

    assert "class SessionConnectionFactory" in header
    assert "DefaultSessionConnectionFactory()" in header
    assert "create(" in header
    assert "AbstractConnection::Create(" in source
    assert "AbstractConnection::Create(" not in session
    assert "_connectionFactory->create(" in session
    assert "not_null<SessionConnectionFactory*> connectionFactory" in private
    assert "DefaultSessionConnectionFactory()" in private
    assert "not_null<SessionConnectionFactory*> _connectionFactory" in private

    for path in (CONNECTION_FACTORY_H, CONNECTION_FACTORY_CPP):
        relative = path.relative_to(SOURCE_DIR).as_posix()
        assert relative in cmake


def test_session_auth_factory_owns_bound_key_creator_creation():
    header = read(AUTH_FACTORY_H)
    source = read(AUTH_FACTORY_CPP)
    auth = read(AUTH_CPP)
    private = read(SESSION_PRIVATE_H)
    cmake = read(CMAKE)

    assert "class SessionBoundKeyCreator" in header
    assert "class SessionAuthKeyFactory" in header
    assert "DefaultSessionAuthKeyFactory()" in header
    assert "std::make_unique<BoundKeyCreator>" in source
    assert "std::make_unique<BoundKeyCreator>" not in auth
    assert "BoundKeyCreator::Delegate" not in auth
    assert "_authKeyFactory->create(" in auth
    assert "std::unique_ptr<SessionBoundKeyCreator> keyCreator;" in private
    assert "not_null<SessionAuthKeyFactory*> _authKeyFactory" in private

    for path in (AUTH_FACTORY_H, AUTH_FACTORY_CPP):
        relative = path.relative_to(SOURCE_DIR).as_posix()
        assert relative in cmake


def test_session_runtime_bound_sources_include_complete_types():
    assert '#include "mtproto/protocol/mtproto_serialized_request.h"' in read(
        AUTH_FACTORY_CPP)

    connection = read(CONNECTION_CPP)
    assert ".context = static_cast<QObject*>(_owner.get())," in connection

    for path in (SESSION_CPP, AUTH_CPP, CONNECTION_CPP, TRANSPORT_CPP):
        assert '#include "mtproto/instance/mtp_instance.h"' in read(path)

    for path in (AUTH_CPP, CONNECTION_CPP, SEND_CPP, TRANSPORT_CPP):
        assert '#include "mtproto/proxy/diagnostics.h"' in read(path)


def test_session_transport_timers_use_runtime_gateway():
	header = read(TRANSPORT_H)
	private = read(SESSION_PRIVATE_H)
	runtime_header = read(SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.h")
	runtime_source = read(SOURCE_DIR / "mtproto" / "runtime" / "runtime_environment.cpp")

	timing = header.split("struct TimingState {", 1)[1].split("\n\t};", 1)[0]
	assert "RuntimeTimer retryTimer;" in timing
	assert "RuntimeTimer oldConnectionTimer;" in timing
	assert "RuntimeTimer waitForConnectedTimer;" in timing
	assert "RuntimeTimer waitForReceivedTimer;" in timing
	assert "RuntimeTimer waitForBetterTimer;" in timing
	assert "RuntimeTimer clearOldContainersTimer;" in timing
	assert "base::Timer" not in timing
	assert '#include "base/timer.h"' not in header
	assert '#include "mtproto/runtime/runtime_environment.h"' in header
	assert "Fn<void(crl::time)> callEach" in runtime_header
	assert "void callEach(crl::time delay)" in runtime_header
	assert "timer->callEach(delay);" in runtime_source
	assert "not_null<RuntimeEnvironment*> runtime" in header
	assert "not_null<QThread*> thread" in header
