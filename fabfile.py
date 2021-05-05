import sys, os, re, shutil
from fabric.api import *
from fabric.contrib import project, files

env.use_ssh_config = True
env.ssh_config_path = '.ssh_config'

env.server_home = '.'
env.server_path_dist = env.server_home + '/micro_backdoor_server'
env.server_cmd_clean = 'rm -rf ' + env.server_path_dist
env.server_cmd_start = './server.py -d'
env.server_cmd_stop = './server.py -s'

env.server_dir = os.path.join(os.getcwd(), 'server')
env.config_dir = os.path.join(os.getcwd(), '_servers')

env.export_dir = os.path.join(os.getcwd(), '_exported')
env.export_srv = os.path.join(env.export_dir, 'server')

env.perm_dir = 700
env.perm_file = 600

def run_if_installed(command):

    if files.exists(env.server_path_dist):

        with cd(env.server_path_dist):

            run(command)

def deps_python():

    packages = [ 'pycrypto', 'm2crypto', 'cherrypy', 'redis', 'defusedxml' ]
    run('sudo -H pip install ' + ' '.join(packages))

def deps_deb():

    packages = [ 'redis-server', 'swig', 'libssl-dev', 'build-essential', 'python', 'python-dev', 'python-setuptools', 'python-pip' ]
    run('sudo apt-get install ' + ' '.join(packages))

''' Install needed dependencies. '''
def deps():

    deps_deb()
    deps_python()

''' Export project from git. '''
def export():

    if os.path.isdir(env.export_dir):

        # delete old files
        shutil.rmtree(env.export_dir)
    
    # export current revision
    local('git checkout-index --prefix=' + env.export_dir + '/ -a')    

''' Remove distro files from server. '''
def clean():

    if files.exists(env.server_path_dist):

        run(env.server_cmd_clean)

''' Upload distro files to server. '''
def upload():

    project.upload_project(env.export_srv, env.server_home)

    run('mv \"%s\" \"%s\"' % (env.server_home + '/' + os.path.basename(env.export_srv), \
                              env.server_path_dist))

    key_path_def = os.path.join(env.server_dir, 'server.key')
    crt_path_def = os.path.join(env.server_dir, 'server.crt')

    key_path = os.path.join(env.config_dir, env.host_string, 'server.key')
    crt_path = os.path.join(env.config_dir, env.host_string, 'server.crt')    

    if os.path.isfile(key_path): 

        # upload host specific key
        project.upload_project(key_path, env.server_path_dist)

    elif os.path.isfile(key_path_def): 

        # upload default key
        project.upload_project(key_path_def, env.server_path_dist)

    else:

        raise(Exception('ERROR: Server private key is not found'))

    if os.path.isfile(crt_path): 

        # upload host specific certificate
        project.upload_project(crt_path, env.server_path_dist)

    elif os.path.isfile(crt_path_def): 

        # upload default certificate
        project.upload_project(crt_path_def, env.server_path_dist)      

    else:

        raise(Exception('ERROR: Server certificate is not found'))  

    # fix permissions
    run('find \"%s\" -type f -print0 | xargs -0 chmod %d' % (env.server_path_dist, env.perm_file))
    run('find \"%s\" -type d -print0 | xargs -0 chmod %d' % (env.server_path_dist, env.perm_dir))
    run('chmod +x %s/server.py' % env.server_path_dist)

''' Start server. '''
def start():

    run('service redis-server start')
    run_if_installed(env.server_cmd_start)

''' Stop server. '''
def stop():

    run_if_installed(env.server_cmd_stop)

''' Restart server. '''
def restart():

    stop()
    start()

''' Uninstall software from server. '''
def uninstall():

    stop()
    clean()

''' Update software version on server. '''
def deploy():    

    export()
    uninstall()
    upload()
    start()

#
# EoF
#
