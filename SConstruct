env = Environment()

if env['PLATFORM'] == 'darwin':
	env.Append(
		CPPPATH = ['/usr/local/opt/openssl/include'],
		LIBPATH = ['/usr/local/opt/openssl/lib'],
	)

if env['PLATFORM'] == 'win32':
	env.Append(
		CXXFLAGS = ['/std:c++latest'],
	)
else:
	env.Append(
		CXXFLAGS = ['-std=c++14', '-Wall', '-O3'],
		LIBS = ['ssl', 'crypto', 'uv']
	)


env.Program('bin/echo', ['echo.cpp'] + Glob('src/*.cpp'))