# 部署
官方文档: https://kubernetes.io/docs/setup/independent/install-kubeadm/#before-you-begin
国内阿里云源安装: https://www.jianshu.com/p/f4dcfbb115ee?utm_source=oschina-app

## 内网关闭防火墙
```sh
systemctl disable firewalld
systemctl stop firewalld
```

## 安装docker容器
```sh
# Install Docker from CentOS/RHEL repository:
yum install -y docker

# or install Docker CE 18.06 from Docker's CentOS repositories:

## Install prerequisites.
yum install yum-utils device-mapper-persistent-data lvm2

## Add docker repository.
yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

## Install docker.
yum update && yum install docker-ce-18.06.1.ce

# Setup daemon.
mkdir /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "registry-mirrors": ["http://6eef2dec.m.daocloud.io"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
EOF

mkdir -p /etc/systemd/system/docker.service.d

# Restart docker.Concern the dockerd run args --default-ulimit nofile=1024:4096.
systemctl daemon-reload
systemctl enable docker
systemctl restart docker
```

## 安装kubelet kubeadm kubectl并运行kubelet
```sh
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kube*
EOF

# 国内用阿里云的源
## CentOS
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=0
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF

## Ubuntu
apt-get update && apt-get install -y apt-transport-https curl
cat <<EOF > /etc/apt/sources.list.d/kubernetes.list
deb http://mirrors.ustc.edu.cn/kubernetes/apt kubernetes-xenial main
EOF
gpg --keyserver keyserver.ubuntu.com --recv-keys BA07F4FB
gpg --export --armor BA07F4FB | sudo apt-key add -

# Set SELinux in permissive mode (effectively disabling it)
setenforce 0
sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config

yum install -y kubelet kubeadm kubectl --disableexcludes=kubernetes
yum install -y kubeadm-1.12.2-0.x86_64 kubelet-1.12.2-0.x86_64 kubectl-1.12.2-0.x86_64 --disableexcludes=kubernetes

# 国内使用阿里云源的pause镜像
## CentOS
cat >/etc/sysconfig/kubelet<<EOF
KUBELET_EXTRA_ARGS="--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google_containers/pause-amd64:3.1"
EOF

## Ubuntu
cat >/etc/default/kubelet<<EOF
KUBELET_EXTRA_ARGS="--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google_containers/pause-amd64:3.1"
EOF

systemctl enable kubelet && systemctl start kubelet


cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF
sysctl --system
```

## 安装kubernetes master
```sh
# 国内修改镜像源为阿里云
# 生成配置文件
cat >kubeadm-master.config<<EOF
apiVersion: kubeadm.k8s.io/v1alpha2
kind: MasterConfiguration
kubernetesVersion: v1.12.1
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
api:
  advertiseAddress: master-ip

controllerManagerExtraArgs:
  node-monitor-grace-period: 10s
  pod-eviction-timeout: 10s

networking:
  podSubnet: 10.244.0.0/16
  
kubeProxy:
  config:
    # mode: ipvs
    mode: iptables
---
apiVersion: kubeadm.k8s.io/v1alpha3
kind: InitConfiguration
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
nodeRegistration:
  kubeletExtraArgs:
    cloud-provider: "aws"
    cloud-config: "/etc/kubernetes/cloud.conf"
---
kind: ClusterConfiguration
apiVersion: kubeadm.k8s.io/v1alpha3
kubernetesVersion: v1.12.0
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers
apiServerExtraArgs:
  cloud-provider: "aws"
  cloud-config: "/etc/kubernetes/cloud.conf"
apiServerExtraVolumes:
- name: cloud
  hostPath: "/etc/kubernetes/cloud.conf"
  mountPath: "/etc/kubernetes/cloud.conf"
controllerManagerExtraArgs:
  cloud-provider: "aws"
  cloud-config: "/etc/kubernetes/cloud.conf"
controllerManagerExtraVolumes:
- name: cloud
  hostPath: "/etc/kubernetes/cloud.conf"
  mountPath: "/etc/kubernetes/cloud.conf"
EOF

# 提前拉取镜像
# 如果执行失败 可以多次执行
kubeadm config images pull --config kubeadm-master.config

# 初始化
kubeadm init --config kubeadm-master.config

[root@k8s-master ~]# kubeadm init
[init] using Kubernetes version: v1.12.1
[preflight] running pre-flight checks
[preflight/images] Pulling images required for setting up a Kubernetes cluster
[preflight/images] This might take a minute or two, depending on the speed of your internet connection
[preflight/images] You can also perform this action in beforehand using 'kubeadm config images pull'
[kubelet] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[kubelet] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[preflight] Activating the kubelet service
[certificates] Generated ca certificate and key.
[certificates] Generated apiserver certificate and key.
[certificates] apiserver serving cert is signed for DNS names [k8s-master kubernetes kubernetes.default kubernetes.default.svc kubernetes.default.svc.cluster.local] and IPs [10.96.0.1 45.76.186.46]
[certificates] Generated apiserver-kubelet-client certificate and key.
[certificates] Generated etcd/ca certificate and key.
[certificates] Generated etcd/healthcheck-client certificate and key.
[certificates] Generated etcd/peer certificate and key.
[certificates] etcd/peer serving cert is signed for DNS names [k8s-master localhost] and IPs [45.76.186.46 127.0.0.1 ::1]
[certificates] Generated apiserver-etcd-client certificate and key.
[certificates] Generated etcd/server certificate and key.
[certificates] etcd/server serving cert is signed for DNS names [k8s-master localhost] and IPs [127.0.0.1 ::1]
[certificates] Generated front-proxy-ca certificate and key.
[certificates] Generated front-proxy-client certificate and key.
[certificates] valid certificates and keys now exist in "/etc/kubernetes/pki"
[certificates] Generated sa key and public key.
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/admin.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/kubelet.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/controller-manager.conf"
[kubeconfig] Wrote KubeConfig file to disk: "/etc/kubernetes/scheduler.conf"
[controlplane] wrote Static Pod manifest for component kube-apiserver to "/etc/kubernetes/manifests/kube-apiserver.yaml"
[controlplane] wrote Static Pod manifest for component kube-controller-manager to "/etc/kubernetes/manifests/kube-controller-manager.yaml"
[controlplane] wrote Static Pod manifest for component kube-scheduler to "/etc/kubernetes/manifests/kube-scheduler.yaml"
[etcd] Wrote Static Pod manifest for a local etcd instance to "/etc/kubernetes/manifests/etcd.yaml"
[init] waiting for the kubelet to boot up the control plane as Static Pods from directory "/etc/kubernetes/manifests" 
[init] this might take a minute or longer if the control plane images have to be pulled
[apiclient] All control plane components are healthy after 24.008665 seconds
[uploadconfig] storing the configuration used in ConfigMap "kubeadm-config" in the "kube-system" Namespace
[kubelet] Creating a ConfigMap "kubelet-config-1.12" in namespace kube-system with the configuration for the kubelets in the cluster
[markmaster] Marking the node k8s-master as master by adding the label "node-role.kubernetes.io/master=''"
[markmaster] Marking the node k8s-master as master by adding the taints [node-role.kubernetes.io/master:NoSchedule]
[patchnode] Uploading the CRI Socket information "/var/run/dockershim.sock" to the Node API object "k8s-master" as an annotation
[bootstraptoken] using token: lvx9gj.ia49bd4wijstc89l
[bootstraptoken] configured RBAC rules to allow Node Bootstrap tokens to post CSRs in order for nodes to get long term certificate credentials
[bootstraptoken] configured RBAC rules to allow the csrapprover controller automatically approve CSRs from a Node Bootstrap Token
[bootstraptoken] configured RBAC rules to allow certificate rotation for all node client certificates in the cluster
[bootstraptoken] creating the "cluster-info" ConfigMap in the "kube-public" namespace
[addons] Applied essential addon: CoreDNS
[addons] Applied essential addon: kube-proxy

Your Kubernetes master has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

You can now join any number of machines by running the following on each node
as root:

  kubeadm join 45.76.186.46:6443 --token lvx9gj.ia49bd4wijstc89l --discovery-token-ca-cert-hash sha256:55a450b89ea1da21cc0dbd019280a0c4c2b127884104602765e90d91e23d3738


```
## 复制配置到用户home
```sh
[root@k8s-master ~]#   mkdir -p $HOME/.kube
[root@k8s-master ~]#   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
[root@k8s-master ~]#   sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## 查看所有pods,发现有两个pods在pending
```sh
[root@k8s ~]# kubectl get pods --all-namespaces
NAMESPACE     NAME                          READY   STATUS    RESTARTS   AGE
kube-system   coredns-576cbf47c7-bfxz2      0/1     Pending   0          7m4s
kube-system   coredns-576cbf47c7-kqvxq      0/1     Pending   0          7m4s
kube-system   etcd-k8s                      1/1     Running   0          6m11s
kube-system   kube-apiserver-k8s            1/1     Running   0          6m28s
kube-system   kube-controller-manager-k8s   1/1     Running   0          6m18s
kube-system   kube-proxy-vptjm              1/1     Running   0          7m4s
kube-system   kube-scheduler-k8s            1/1     Running   0          6m5s
```

## 查看原因
```sh
[root@k8s ~]# kubectl --namespace=kube-system describe pod coredns-576cbf47c7-bfxz2
Name:               coredns-576cbf47c7-bfxz2
Namespace:          kube-system
Priority:           0
PriorityClassName:  <none>
Node:               <none>
Labels:             k8s-app=kube-dns
                    pod-template-hash=576cbf47c7
Annotations:        <none>
Status:             Pending
IP:                 
Controlled By:      ReplicaSet/coredns-576cbf47c7
Containers:
  coredns:
    Image:       k8s.gcr.io/coredns:1.2.2
    Ports:       53/UDP, 53/TCP, 9153/TCP
    Host Ports:  0/UDP, 0/TCP, 0/TCP
    Args:
      -conf
      /etc/coredns/Corefile
    Limits:
      memory:  170Mi
    Requests:
      cpu:        100m
      memory:     70Mi
    Liveness:     http-get http://:8080/health delay=60s timeout=5s period=10s #success=1 #failure=5
    Environment:  <none>
    Mounts:
      /etc/coredns from config-volume (ro)
      /var/run/secrets/kubernetes.io/serviceaccount from coredns-token-f5fps (ro)
Conditions:
  Type           Status
  PodScheduled   False 
Volumes:
  config-volume:
    Type:      ConfigMap (a volume populated by a ConfigMap)
    Name:      coredns
    Optional:  false
  coredns-token-f5fps:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  coredns-token-f5fps
    Optional:    false
QoS Class:       Burstable
Node-Selectors:  <none>
Tolerations:     CriticalAddonsOnly
                 node-role.kubernetes.io/master:NoSchedule
                 node.kubernetes.io/not-ready:NoExecute for 300s
                 node.kubernetes.io/unreachable:NoExecute for 300s
Events:
  Type     Reason            Age                    From               Message
  ----     ------            ----                   ----               -------
  Warning  FailedScheduling  2m8s (x35 over 7m10s)  default-scheduler  0/1 nodes are available: 1 node(s) had taints that the pod didn't tolerate.
```
## 只有一个node,而且是master, 因为taint配置不能将这两个pods调度到这个node

## 取消master taint配置,还是pending
```sh
[root@k8s ~]# kubectl taint nodes --all node-role.kubernetes.io/master-
node/k8s untainted
[root@k8s ~]# kubectl get pods --all-namespaces
NAMESPACE     NAME                          READY   STATUS    RESTARTS   AGE
kube-system   coredns-576cbf47c7-bfxz2      0/1     Pending   0          5m38s
kube-system   coredns-576cbf47c7-kqvxq      0/1     Pending   0          5m38s
kube-system   etcd-k8s                      1/1     Running   0          4m45s
kube-system   kube-apiserver-k8s            1/1     Running   0          5m2s
kube-system   kube-controller-manager-k8s   1/1     Running   0          4m52s
kube-system   kube-proxy-vptjm              1/1     Running   0          5m38s
kube-system   kube-scheduler-k8s            1/1     Running   0          4m39s
```

## 查看node状态,master为NoReady,安装CNI网络插件
```sh
[root@k8s ~]# kubectl get nodes
NAME   STATUS     ROLES    AGE     VERSION
k8s    NotReady   master   8m34s   v1.12.1
[root@k8s ~]# kubectl apply -f https://git.io/weave-kube-1.6
serviceaccount/weave-net created
clusterrole.rbac.authorization.k8s.io/weave-net created
clusterrolebinding.rbac.authorization.k8s.io/weave-net created
role.rbac.authorization.k8s.io/weave-net created
rolebinding.rbac.authorization.k8s.io/weave-net created
daemonset.extensions/weave-net created
```

## 安装完网络插件后一段时间,node状态变为Ready,pods调度成功
```sh
[root@k8s ~]# kubectl get nodes
NAME   STATUS   ROLES    AGE    VERSION
k8s    Ready    master   9m4s   v1.12.1
[root@k8s ~]# kubectl get pods --all-namespaces
NAMESPACE     NAME                          READY   STATUS    RESTARTS   AGE
kube-system   coredns-576cbf47c7-bfxz2      1/1     Running   0          11m
kube-system   coredns-576cbf47c7-kqvxq      1/1     Running   0          11m
kube-system   etcd-k8s                      1/1     Running   0          10m
kube-system   kube-apiserver-k8s            1/1     Running   0          10m
kube-system   kube-controller-manager-k8s   1/1     Running   2          10m
kube-system   kube-proxy-vptjm              1/1     Running   0          11m
kube-system   kube-scheduler-k8s            1/1     Running   2          10m
kube-system   weave-net-z6djf               2/2     Running   0          3m14s
```

*如果CPU或者RAM不足可能导致部分pod退出*
```sh
[root@k8s ~]# kubectl get pods --all-namespaces
NAMESPACE     NAME                          READY   STATUS             RESTARTS   AGE
kube-system   coredns-576cbf47c7-bfxz2      1/1     Running            1          13m
kube-system   coredns-576cbf47c7-kqvxq      1/1     Running            1          13m
kube-system   etcd-k8s                      1/1     Running            0          12m
kube-system   kube-apiserver-k8s            1/1     Running            0          12m
kube-system   kube-controller-manager-k8s   0/1     CrashLoopBackOff   3          12m
kube-system   kube-proxy-vptjm              1/1     Running            0          13m
kube-system   kube-scheduler-k8s            0/1     CrashLoopBackOff   3          12m
kube-system   weave-net-z6djf               2/2     Running            1          4m42s
```


## 添加node
- 内网关闭防火墙
- 安装docker容器
- 安装kubelet kubeadm kubectl并运行kublet
- 添加node到集群

`忘记初始master节点时的node节点加入集群命令怎么办`
```sh
# 简单方法
kubeadm token create --print-join-command

# 第二种方法
token=$(kubeadm token generate)
kubeadm token create $token --print-join-command --ttl=0
```

```sh
[root@k8s-node ~]#   kubeadm join 45.76.186.46:6443 --token lvx9gj.ia49bd4wijstc89l --discovery-token-ca-cert-hash sha256:55a450b89ea1da21cc0dbd019280a0c4c2b127884104602765e90d91e23d3738
[preflight] running pre-flight checks
	[WARNING RequiredIPVSKernelModulesAvailable]: the IPVS proxier will not be used, because the following required kernel modules are not loaded: [ip_vs ip_vs_rr ip_vs_wrr ip_vs_sh] or no builtin kernel ipvs support: map[ip_vs:{} ip_vs_rr:{} ip_vs_wrr:{} ip_vs_sh:{} nf_conntrack_ipv4:{}]
you can solve this problem with following methods:
 1. Run 'modprobe -- ' to load missing kernel modules;
2. Provide the missing builtin kernel ipvs support

[discovery] Trying to connect to API Server "45.76.186.46:6443"
[discovery] Created cluster-info discovery client, requesting info from "https://45.76.186.46:6443"
[discovery] Requesting info from "https://45.76.186.46:6443" again to validate TLS against the pinned public key
[discovery] Cluster info signature and contents are valid and TLS certificate validates against pinned roots, will use API Server "45.76.186.46:6443"
[discovery] Successfully established connection with API Server "45.76.186.46:6443"
[kubelet] Downloading configuration for the kubelet from the "kubelet-config-1.12" ConfigMap in the kube-system namespace
[kubelet] Writing kubelet configuration to file "/var/lib/kubelet/config.yaml"
[kubelet] Writing kubelet environment file with flags to file "/var/lib/kubelet/kubeadm-flags.env"
[preflight] Activating the kubelet service
[tlsbootstrap] Waiting for the kubelet to perform the TLS Bootstrap...
[patchnode] Uploading the CRI Socket information "/var/run/dockershim.sock" to the Node API object "k8s-node" as an annotation

This node has joined the cluster:
* Certificate signing request was sent to apiserver and a response was received.
* The Kubelet was informed of the new secure connection details.

Run 'kubectl get nodes' on the master to see this node join the cluster.
```
- 安装网络插件报错
```sh
[root@k8s-node ~]# kubectl apply -f https://git.io/weave-kube-1.6
error: unable to recognize "https://git.io/weave-kube-1.6": Get http://localhost:8080/api?timeout=32s: dial tcp [::1]:8080: connect: connection refused
```
- 将master下的$HOEM/.kube文件夹复制过来, 再重新安装网络插件
```sh
[root@k8s-node ~]# kubectl apply -f https://git.io/weave-kube-1.6
serviceaccount/weave-net unchanged
clusterrole.rbac.authorization.k8s.io/weave-net unchanged
clusterrolebinding.rbac.authorization.k8s.io/weave-net unchanged
role.rbac.authorization.k8s.io/weave-net unchanged
rolebinding.rbac.authorization.k8s.io/weave-net unchanged
daemonset.extensions/weave-net configured
```

# 修改kube-apiserver等服务启动参数
```sh
[root@iZbp18eqmbj0rd1a88dd4lZ ~]# ls /etc/kubernetes/manifests/
etcd.yaml  kube-apiserver.yaml  kube-controller-manager.yaml  kube-scheduler.yaml
[root@iZbp18eqmbj0rd1a88dd4lZ ~]# cat /var/lib/kubelet/config.yaml | grep staticPodPath
staticPodPath: /etc/kubernetes/manifests
```
修改这几个文件的参数,然后重启kubelet,kubelet会重新启动静态Pod

