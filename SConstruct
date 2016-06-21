#!python

#export LD_LIBRARY_PATH=/usr/local/lib

env = Environment(CCFLAGS = '-g')
env.Append(CPPPATH = ['headers'], LIBS=['-lconfig', '-lcrypto', '-lssl', '-lpthread'])

server = env.Object('src/server/server.c')
server_init = env.Object('src/server/server_init.c')


#client = env.Object('client/client.c')
#client_main = env.Object('client/client_main.c')

hash_table = env.Object('src/server/hashtable.c')

env.Program(target = ['src/server.out'], source = server + server_init + hash_table)
#env.Program(target = ['client.out'], source = client + client_main)
