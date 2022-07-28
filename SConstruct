environment = Environment()

if environment['PLATFORM'] == 'darwin':
	environment.Append(
		CPPPATH = ['/usr/local/opt/openssl/include'],
		LIBPATH = ['/usr/local/opt/openssl/lib'],
	)

if environment['PLATFORM'] == 'win32':
	environment.Append(
		CXXFLAGS = ['/std:c++latest'],
	)
else:
	environment.Append(
		CXXFLAGS = ['-std=c++17', '-Wall', '-O0', '-g'],
		LINKFLAGS = ['-O0', '-g'],
		LIBS = ['ssl', 'crypto', 'uv'],
	)


environment.Program('bin/echo', ['echo.cpp'] + Glob('src/*.cpp'))
