
env = Environment(
	CXXFLAGS = ['-std=c++14', '-Wall'],
	LIBS = ['ssl', 'crypto', 'uv']
)

if env['PLATFORM'] == 'darwin':
	env.Append(
		CPPPATH = ['/usr/local/opt/openssl/include'],
		LIBPATH = ['/usr/local/opt/openssl/lib'],
	)


env.Program('bin/echo', ['echo.cpp'] + Glob('src/*.cpp'))