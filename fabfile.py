"""

Fabric script to deploy Docker swarm to my Trinity cluster,
try some inter-container/cross-host connectivity,
and deploy solr.

Work in progress.

"""
from fabric.api import env, run, sudo, execute, settings, roles
from fabric.contrib.files import exists, append, put, upload_template
from fabric.network import disconnect_all
from fabric.decorators import parallel
from fabric.context_managers import shell_env
import time, os, re, string, random, StringIO

# define cluster IPs
env.cluster_address = {
    'trinity10': '192.168.77.10',
    'trinity20': '192.168.77.20',
    'trinity30': '192.168.77.30'
}

env.roledefs = {
    'all': sorted(env.cluster_address.keys()),
    'etcd': sorted(env.cluster_address.keys()),
    'docker_cli': ['trinity10'],
    'swarm_master': ['trinity10'],
    'alpha_dockerhost': ['trinity10'],
    'beta_dockerhost': ['trinity20'],
    'zookeeperdockerhost': ['trinity10'],
    'solr1dockerhost': ['trinity10'],
    'solr2dockerhost': ['trinity20'],
    'solrclientdockerhost': ['trinity30'],
}
env.etcd_host = "trinity10"
env.etcd_cluster_token = "etcd-cluster-2123"
env.user = "mak"

SOLR_IMAGE = 'makuk66/docker-solr:5.2-no-expose'
ZOOKEEPER_IMAGE = 'jplock/zookeeper'
ZOOKEEPER_NAME = 'zookeeper1'

BUSYBOX_IMAGE = 'busybox:latest'
UBUNTU_IMAGE = 'ubuntu:latest'
ETCD_URL="https://github.com/coreos/etcd/releases/download/v2.2.1/etcd-v2.2.1-linux-amd64.tar.gz"
HAPROXY_IMAGE="haproxy:1.6"
SOLR_COLLECTION = "sample"

NET_ALPHA_BETA = "netalphabeta"
NET_SOLR = "netsolr"

TEST_ALPHA = "alpha"
TEST_BETA = "beta"

env.etcd_client_port = 2379
env.etcd_peer_port = 7001

env.docker_port = 2375
env.swarm_master_port = 3375

TEMPLATES = 'templates'

def get_docker_host_for_role(role):
    """ get the docker host for a container role """
    return env.roledefs[role][0]

def get_swarm_url():
    swarm_master_ip = env.cluster_address[env.roledefs['swarm_master'][0]]
    return 'tcp://{}:{}'.format(swarm_master_ip, env.swarm_master_port)

@roles('all')
def info():
    """ Show machine information """
    run('cat /etc/lsb-release')
    run('uname -a')

@roles('all')
def ping():
    """ Ping all the hosts in the cluster from this host """
    for name in sorted(env.cluster_address.keys()):
        run("ping -c 3 {}".format(env.cluster_address[name]))

@roles('all')
def copy_ssh_key(ssh_pub_key="~/.ssh/id_dsa.pub", user=env.user):
    """ Copy the local ssh key to the cluster machines """
    ssh_pub_key_path = os.path.expanduser(ssh_pub_key)
    remote = "tmpkey.pem"
    put(ssh_pub_key_path, remote)
    sudo("mkdir -p ~{}/.ssh".format(user))
    sudo("cat ~{}/{} >> ~{}/.ssh/authorized_keys".format(user, remote, user))
    sudo("chown {}:{} ~{}/.ssh".format(user, user, user))
    sudo("chown {}:{} ~{}/.ssh/authorized_keys".format(user, user, user))
    sudo("rm ~{}/{}".format(user, remote))

    #sudo("mkdir -p ~root/.ssh")
    #sudo("cat ~{}/.ssh/authorized_keys >> ~root/.ssh/authorized_keys".format(user, remote, user))
    #sudo("chown root:root ~root/.ssh/authorized_keys")

@roles('all')
def setup_sudoers():
    """ Add the user to sudoers, allowing password-less sudo """
    append("/etc/sudoers", "{0}  ALL=(ALL) NOPASSWD:ALL".format(env.user), use_sudo=True)

@roles('all')
def install_docker():
    if exists('/usr/bin/docker'):
        return

    # per http://docs.docker.com/engine/installation/ubuntulinux/
    sudo("apt-key adv --keyserver hkp://pgp.mit.edu:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D")

    distrib_codename = run("grep DISTRIB_CODENAME /etc/lsb-release |sed 's/.*=//'")
    put(StringIO.StringIO('deb https://apt.dockerproject.org/repo ubuntu-{} main\n'.format(distrib_codename)),
        '/etc/apt/sources.list.d/docker.list', use_sudo=True)
    sudo('apt-get --yes --quiet update')
    sudo('apt-cache policy docker-engine')
    sudo('apt-get --yes --quiet install docker-engine')
    sudo('adduser {} docker'.format(env.user))
    sudo('sudo service docker restart')
    time.sleep(5)
    disconnect_all() # so we reconnect and to group applies.
    run("docker version")

@roles('all')
def docker_version():
    """ display docker version and status """
    run('docker version')
    run('status docker')

@roles('all')
def remove_everything():
    # kill all containers
    run("docker ps --format '{{ .ID }}' --no-trunc | xargs -n 1 --no-run-if-empty docker kill")
    # remove all containers
    run("docker ps --all --format '{{ .ID }}' --no-trunc | xargs -n 1 --no-run-if-empty docker rm")
    # remove all volumes
    run("docker volume ls | tail -n +2 | awk '{print $2}' | xargs -n 1 --no-run-if-empty docker volume rm")
    # remove all images
    run("docker images| tail -n +2 | awk '{print $3}' | xargs -n 1 --no-run-if-empty docker rmi")
    # remove networks
    sudo('service docker stop || true')
    sudo('service etcd stop || true')
    sudo('rm -f /etc/init/etcd.conf /etc/default/docker')
    # TODO: now remove leftover mount pounts. Maybe something like
    if exists('/var/lib/docker'):
        docker_libdir=run("readlink /var/lib/docker/ || true")
        if docker_libdir == "":
            docker_libdir = '/var/lib/docker'
        sudo("grep {} /proc/mounts | xargs -n 1 --no-run-if-empty umount -f".format(docker_libdir))
        sudo('rm -fr {}'.format(docker_libdir))
    if exists('/run/docker'):
        docker_rundir=run("readlink /run/docker/ || true")
        if docker_rundir == "":
            docker_rundir = '/run/docker'
        # TODO: do we need something special for /run/docker/netns/* ?
        sudo('rm -fr {}'.format(docker_rundir))
    sudo('apt-get --yes purge docker-engine')
    sudo('rm -fr /run/docker.pid /run/docker.sock')
    # Note: etc uses the current directory to place the data subdirectory, and in the upstart config we
    # chdir to the etcd source directory. Etcd then creates a subdirectory, owned by root.
    # So we need to be root to remove this. TODO: run etcd under an "etcd" user.
    sudo('rm -fr etcd*')
    sudo('rm -fr /var/log/upstart/docker.log /var/log/upstart/etcd.log')

@roles('all')
def install_prerequisites():
    """ install OS pre-requisites """
    sudo("modprobe ip6_tables")
    append("/etc/modules", "ip6_tables", use_sudo=True)
    sudo("modprobe xt_set")
    append("/etc/modules", "xt_set", use_sudo=True)
    sudo("sysctl -w net.ipv6.conf.all.forwarding=1")
    sudo("echo net.ipv6.conf.all.forwarding=1 > /etc/sysctl.d/60-ipv6-forwarding.conf")
    sudo("apt-get install --yes --quiet unzip curl git")

def get_addressv4_address():
    """ utility method to return the ip address for the current host """
    ipv4_address = run("ip -4 addr show dev eth0 | "
                       "grep inet | awk '{print $2}' | sed -e 's,/.*,,'")
    if not re.match(r'^\d+\.\d+\.\d+\.\d+', ipv4_address):
        raise Exception("cannot get IP address")
    return ipv4_address

@roles('etcd')
def install_etcd():
    """ install etcd """
    # See https://github.com/coreos/etcd/blob/master/Documentation/clustering.md#static
    my_name = "etcd-{}".format(env.host)
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("etcd-{}=http://{}:{}".format(name, ipv4_address, env.etcd_peer_port))
    initial_cluster = ",".join(initial_cluster_members)

    etc_tgz = ETCD_URL.rpartition('/')[2]
    etc_dir = etc_tgz.replace('.tar.gz', '')
    if not exists(etc_tgz):
        run("wget -nv {}".format(ETCD_URL))
    if not exists(etc_dir):
        run("tar xvzf {}".format(etc_tgz))
    etcd_home = run("cd {}; /bin/pwd".format(etc_dir))
    ipv4_address = get_addressv4_address()
    ctx = {
        "name": my_name,
        "etcd_home": etcd_home,
        "advertise_client_urls": 'http://{}:{}'.format(ipv4_address, env.etcd_client_port),
        "listen_client_urls": 'http://0.0.0.0:{}'.format(env.etcd_client_port),
        "advertise_peer_urls": 'http://{}:{}'.format(ipv4_address, env.etcd_peer_port),
        "etcd_peer_port": env.etcd_peer_port,
        "initial_cluster": initial_cluster
    }
    upload_template(filename='etcd.conf', destination='/etc/init/etcd.conf',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True)

    sudo("service etcd start")
    time.sleep(2)

@roles('etcd')
def install_docker_config():
    # configure Docker to use our etcd cluster
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("{}:{}".format(ipv4_address, env.etcd_client_port))
    initial_cluster = ",".join(initial_cluster_members)

    # update DOCKER_OPTS. Note this also changes the -H to listen on tcp
    ctx = {
        "listen": "{}:{}".format(env.cluster_address[env.host], env.docker_port),
        "cluster_store": "etcd://{}".format(initial_cluster),
        "cluster_advertise": "{}:{}".format(env.cluster_address[env.host], env.docker_port)

    }
    upload_template(filename='docker.default', destination='/etc/default/docker',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True)


    sudo("service docker restart")
    time.sleep(5)


@roles('etcd')
def remove_etcd():
    sudo("service etcd stop || true")
    sudo("rm -fr etcd* /etc/init/etcd.conf /var/log/upstart/etcd.log")

@roles('all')
def docker_clean():
    """ remove containers that have exited """
    run("docker rm `docker ps --no-trunc --all --quiet --filter=status=exited`")

@roles('etcd')
def check_etcd():
    """ check etcd: on each etcd host, talk to the local etcd server """
    run("curl -L http://{}:{}/version".format("localhost", env.etcd_client_port))
    run("curl -L http://{}:{}/v2/machines".format("localhost", env.etcd_client_port))

@roles('all')
def install_go():
    url="https://storage.googleapis.com/golang/go1.5.1.linux-amd64.tar.gz"
    filename = url.rpartition('/')[2]
    target='/tmp/' + filename
    if not exists(target):
        run("wget -nv {} -O {}".format(url, target))
    sudo("tar -C /usr/local -xzf {}".format(target))
    #run("rm {}".format(target))

    golang_profile = '/etc/profile.d/golang.sh'
    put('files/golang.profile', golang_profile, use_sudo=True)
    run("source {}; go get github.com/tools/godep".format(golang_profile))

@roles('all')
@parallel
def install_swarm():
    run("go get github.com/docker/swarm")

@roles('all')
def install_swarm_agent():
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("{}:{}".format(ipv4_address, env.etcd_client_port))
    initial_cluster = ",".join(initial_cluster_members)

    ipv4_address = get_addressv4_address()
    ctx = {
        "advertise_hostport": "{}:{}".format(ipv4_address, env.docker_port),
        "cluster": 'etcd://{}/'.format(initial_cluster)
    }
    upload_template(filename='swarm-agent.conf', destination='/etc/init/swarm-agent.conf',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True)
    sudo("service swarm-agent stop || true")
    sudo("rm -f /var/log/upstart/swarm-agent.log")
    sudo("service swarm-agent start")
    time.sleep(3)
    sudo("tail /var/log/upstart/swarm-agent.log")

@roles('swarm_master')
def install_swarm_master():
    initial_cluster_members = []
    for name in sorted(env.cluster_address.keys()):
        ipv4_address = env.cluster_address[name]
        initial_cluster_members.append("{}:{}".format(ipv4_address, env.etcd_client_port))
    initial_cluster = ",".join(initial_cluster_members)

    ipv4_address = get_addressv4_address()
    ctx = {
        "swarm_master_port": env.swarm_master_port,
        "cluster": 'etcd://{}/'.format(initial_cluster)
    }
    upload_template(filename='swarm-master.conf', destination='/etc/init/swarm-master.conf',
                    template_dir=TEMPLATES, context=ctx, use_sudo=True, use_jinja=True)
    sudo("service swarm-master stop || true")
    sudo("rm -f /var/log/upstart/swarm-master.log")
    sudo("service swarm-master start")
    time.sleep(3)
    sudo("tail /var/log/upstart/swarm-master.log")

@roles('docker_cli')
def swarm_info():
    run("DOCKER_HOST={} docker info".format(get_swarm_url()))

@roles('docker_cli')
def create_networks():
    """ create two example networks """
    etcd_address = env.cluster_address[env.roledefs['etcd'][0]]
    with shell_env(ETCD_AUTHORITY='{}:{}'.format(etcd_address, env.etcd_client_port)):
        run("docker network create --driver=overlay --subnet 192.168.91.0/24 " + NET_ALPHA_BETA)
        run("docker network create --driver=overlay --subnet 192.168.89.0/24 " + NET_SOLR)
        run("docker network ls")

@roles('docker_cli')
def create_test_container_alpha():
    """ create first test container """
    create_test_container(TEST_ALPHA, env.roledefs['alpha_dockerhost'][0])

@roles('docker_cli')
def create_test_container_beta():
    """ create second test container """
    create_test_container(TEST_BETA, env.roledefs['beta_dockerhost'][0])

# http://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits-in-python
def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    """ return a random identifier """
    return ''.join(random.choice(chars) for _ in range(size))

def create_test_container(name='', node='', image=BUSYBOX_IMAGE):
    """ create a test container """
    container_name = 'c-' + name
    with shell_env(DOCKER_HOST=get_swarm_url()):
        run("docker pull {}".format(image), pty=False)
        container_id = run("docker run -e constraint:node=={} --net {} --name {} --hostname={}.{} -tid {}".format(
            node, NET_ALPHA_BETA, container_name, container_name, NET_ALPHA_BETA, image))
        inspect_container(container_id)

def inspect_container(container_name_or_id=''):
    """ e.g. fab --host trinity10 inspect_container:container_name_or_id=... """
    with shell_env(DOCKER_HOST=get_swarm_url()):
        container_id = run("docker inspect --format '{{.Id}}' " + container_name_or_id)
        container_name = run("docker inspect --format '{{.Name}}' " + container_name_or_id)
        if container_name[0] == '/':
            container_name = container_name[1:]
        net = run("docker inspect --format '{{ .HostConfig.NetworkMode }}' " + container_id)
        ip_address = run("docker inspect --format '{{ .NetworkSettings.Networks." + net + ".IPAddress }}' " + container_id)
        print "container_id={}, container_name={}, ip_address={}".format(
            container_id, container_name, ip_address)
        run("docker exec -i {} hostname".format(container_id))

        with settings(warn_only=True):
            run("docker exec -i {} ls -l /sys/devices/virtual/net/".format(container_id))
            run("docker exec -i {} ip link list".format(container_id))
            run("docker exec -i {} ip addr list".format(container_id))
            run("docker exec -i {} ip route list".format(container_id))

@roles('swarm_master')
def ping_test_containers():
    """ see if containers A and B can ping eachother """
    alpha_name = 'c-' + TEST_ALPHA
    beta_name = 'c-' + TEST_BETA
    with shell_env(DOCKER_HOST=get_swarm_url()):
        run("docker exec -i {} ping -c 1 {}.{}".format(alpha_name, beta_name, NET_ALPHA_BETA))
        run("docker exec -i {} ping -c 1 {}.{}".format(beta_name, alpha_name, NET_ALPHA_BETA))

    #with settings(host_string=get_docker_host_for_role('alpha_dockerhost')):
    #    run("docker exec -i {} ping -c 1 {}.{}".format(alpha_name, beta_name, NET_ALPHA_BETA)#)
    #with settings(host_string=get_docker_host_for_role('beta_dockerhost')):
    #    run("docker exec -i {} ping -c 1 {}.{}".format(beta_name, alpha_name, NET_ALPHA_BETA))

@roles('docker_cli')
def create_test_zookeeper():
    """ create zookeeper container """
    with shell_env(DOCKER_HOST=get_swarm_url()):
        run("docker pull {}".format(ZOOKEEPER_IMAGE), pty=False)
        container_id = run("docker run --net {} --name {} -e contraint:node=={} --hostname={}.{} -tid {}".format(
            NET_SOLR, ZOOKEEPER_NAME, env.roledefs['zookeeperdockerhost'][0], ZOOKEEPER_NAME, NET_SOLR, ZOOKEEPER_IMAGE))
        time.sleep(3)
        inspect_container(ZOOKEEPER_NAME)

@roles('all')
@parallel
def pull_docker_images():
    """ pull images we'll use """
    for image in [SOLR_IMAGE, ZOOKEEPER_IMAGE, BUSYBOX_IMAGE, UBUNTU_IMAGE, HAPROXY_IMAGE]:
        run("docker pull {}".format(image), pty=False)

@roles('docker_cli')
def create_test_solr1():
    """ create a first Solr container """
    create_test_solr("solr1")

@roles('docker_cli')
def create_test_solr2():
    """ create a second Solr container """
    create_test_solr("solr2")

def create_test_solr(name):
    """ create a container running solr """
    dockerhost = env.roledefs[name + 'dockerhost'][0]
    run("docker pull {}".format(SOLR_IMAGE), pty=False)
    with shell_env(DOCKER_HOST=get_swarm_url()):
        zookeeper_address = run("docker inspect --format '{{ .NetworkSettings.Networks." + NET_SOLR + ".IPAddress }}' " + ZOOKEEPER_NAME)
        container_id = run("docker run --net {} --name {} --hostname={}.{} --label=solr -e contraint:node=={} -p 8983 -tid {} bash -c '/opt/solr/bin/solr start -f -z {}:2181'".format(
        NET_SOLR, name, name, NET_SOLR, dockerhost, SOLR_IMAGE, zookeeper_address))
    
        time.sleep(5) # does this help "Error: No such image or container:"?
        inspect_container(name)

        time.sleep(15)

        run("docker logs {}".format(container_name))

def foo():
    with shell_env(DOCKER_HOST=get_swarm_url()):
        run("docker logs solr1| tr -d '\r'")


@roles('docker_cli')
def create_test_solrclient():
    """ talk to both solr nodes from a container """
    # TODO: why does this now take 5s?
    with shell_env(DOCKER_HOST=get_swarm_url()):
        name = 'solrclient-' + id_generator()
        run("docker run --net {} --name {} --hostname {}.{} -i {} curl -sSL http://solr1.{}:8983/".format(NET_SOLR, name, name, NET_SOLR, SOLR_IMAGE, NET_SOLR))
        name = 'solrclient-' + id_generator()
        run("docker run --net {} --name {} --hostname {}.{} -i {} curl -sSL http://solr2.{}:8983/".format(NET_SOLR, name, name, NET_SOLR, SOLR_IMAGE, NET_SOLR))

@roles('docker_cli')
def solr_collection():
    """ create collection in solr """
    with shell_env(DOCKER_HOST=get_swarm_url()):
       run("docker exec -i -t solr1 /opt/solr/bin/solr "
            "create_collection -c {} -shards 2 -p 8983 | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))

@roles('docker_cli')
def solr_data():
    """ load test data into solr """
    with shell_env(DOCKER_HOST=get_swarm_url()):
        run("docker exec -it --user=solr solr1 "
            "bin/post -c {} /opt/solr/example/exampledocs/manufacturers.xml | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))

@roles('docker_cli')
def solr_query():
    """ query solr """
    with shell_env(DOCKER_HOST=get_swarm_url()):
        print "demonstrate you can query either server and get a response:"
        response = run("docker exec -it --user=solr solr1 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true' | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))
        if 'numFound="1"' in response:
            print "got one found, as expected"
        else:
            print "none found!"
        run("docker exec -it --user=solr solr2 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true' | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION))
        if 'numFound="1"' in response:
            print "got one found, as expected"
        else:
            print "none found!"

        print "demonstrate the response only comes from a single shard:"
        response1 = run("docker exec -it --user=solr solr1 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true&shards=localhost:8983/solr/{}_shard1_replica1' | tr -d '\r' | grep -v '^$'".format(SOLR_COLLECTION, SOLR_COLLECTION))
        response2 = run("docker exec -it --user=solr solr1 "
            "curl 'http://localhost:8983/solr/{}/select?q=maxtor&indent=true&shards=localhost:8983/solr/{}_shard2_replica1' | tr -d '\r' | grep -v '^$' ".format(SOLR_COLLECTION, SOLR_COLLECTION))
        if (('numFound="1"' in response1) or ('numFound="1"' in response2)) and not ('numFound="1"' in response1 and 'numFound="1"' in response2):
            print "found only in one shard, as expected"
        else:
            print "ehr?!"

@roles('all')
def docker_ps():
    """ run docker ps """
    run('docker ps')

def install():
    """ install the cluster """
    # I've not run this in a single go; but it illustrates the order
    execute(info)
    execute(copy_ssh_key)
    execute(setup_sudoers)
    execute(install_prerequisites)
    execute(install_docker)
    execute(docker_version)
    execute(pull_docker_images)
    execute(install_etcd)
    execute(install_docker_config)
    execute(check_etcd)

    execute(install_go)
    execute(install_swarm)
    execute(install_swarm_agent)
    execute(install_swarm_master)
    execute(swarm_info)

    execute(create_networks)

    execute(create_test_container_alpha)
    execute(create_test_container_beta)
    execute(ping_test_containers)

    execute(create_test_zookeeper)
    execute(create_test_solr1)
    execute(create_test_solr2)

    execute(create_test_solrclient)
    execute(solr_collection)
    execute(solr_data)
    execute(solr_query)

    


