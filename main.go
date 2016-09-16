package main

import (
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang/glog"

	"k8s.io/client-go/1.4/kubernetes"
	"k8s.io/client-go/1.4/pkg/util/wait"
	"k8s.io/client-go/1.4/rest"
)

var (
	provisionerName = flag.String("provisioner-name", "matthew/nfs", "The name of this provisioner, i.e. the value `StorageClasses` will set for their `provisioner`.")
)

func main() {
	flag.Set("logtostderr", "true")
	flag.Parse()

	// Start the NFS server
	startServer()

	// On interrupt or SIGTERM, stop the NFS server
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		stopServer()
		os.Exit(1)
	}()

	// TODO out of cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		glog.Fatalf("Failed to create config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatalf("Failed to create client: %v", err)
	}

	// TODO is this useful?
	// Statically provision NFS PVs specified in exports.json, if exists
	err = provisionStatic(clientset, "/etc/config/exports.json")
	if err != nil {
		glog.Errorf("Error while provisioning static exports: %v", err)
	}

	// Start the NFS controller which will dynamically provision NFS PVs
	nc := newNfsController(clientset, 15*time.Second, *provisionerName)
	nc.Run(wait.NeverStop)
}

// startServer is based on start in https://github.com/kubernetes/kubernetes/blob/release-1.4/examples/volumes/nfs/nfs-data/run_nfs.sh
// It Fatals on any error.
func startServer() {
	glog.Info("Starting NFS")

	// Start rpcbind if it is not started yet
	cmd := exec.Command("/usr/sbin/rpcinfo", "127.0.0.1")
	if err := cmd.Run(); err != nil {
		glog.Info("Starting rpcbind")
		cmd := exec.Command("/usr/sbin/rpcbind", "-w")
		if err := cmd.Run(); err != nil {
			glog.Fatalf("Starting rpcbind failed: %v", err)
		}
	}

	// Mount the nfsd filesystem to /proc/fs/nfsd
	cmd = exec.Command("mount", "-t", "nfsd", "nfsd", "/proc/fs/nfsd")
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Fatalf("mount nfsd failed with error: %v, output: %v", err, out)
	}

	// -N 4.x: disable NFSv4
	// -V 3: enable NFSv3
	cmd = exec.Command("/usr/sbin/rpc.mountd", "-N2", "-V3", "-N4", "-N4.1")
	if err := cmd.Run(); err != nil {
		glog.Fatalf("rpc.mountd failed: %v", err)
	}

	// -G 10 to reduce grace period to 10 seconds (the lowest allowed)
	cmd = exec.Command("/usr/sbin/rpc.nfsd", "-G10", "-N2", "-V3", "-N4", "-N4.1", "2")
	if err := cmd.Run(); err != nil {
		glog.Fatalf("rpc.nfsd failed: %v", err)
	}

	cmd = exec.Command("/usr/sbin/rpc.statd", "--no-notify")
	if err := cmd.Run(); err != nil {
		glog.Fatalf("rpc.statd failed: %v", err)
	}

	glog.Info("NFS started")
}

// stopServer is based on stop in https://github.com/kubernetes/kubernetes/blob/release-1.4/examples/volumes/nfs/nfs-data/run_nfs.sh
func stopServer() {
	glog.Info("Stopping NFS")

	cmd := exec.Command("/usr/sbin/rpc.nfsd", "0")
	if err := cmd.Run(); err != nil {
		glog.Errorf("rpc.nfsd failed: %v", err)
	}

	cmd = exec.Command("/usr/sbin/exportfs", "-au")
	if err := cmd.Run(); err != nil {
		glog.Errorf("exportfs -au failed: %v", err)
	}

	cmd = exec.Command("/usr/sbin/exportfs", "-f")
	if err := cmd.Run(); err != nil {
		glog.Errorf("exportfs -f failed: %v", err)
	}

	cmd = exec.Command("kill", "$( pidof rpc.mountd )")
	if err := cmd.Run(); err != nil {
		glog.Errorf("kill rpc.mountd failed: %v", err)
	}

	cmd = exec.Command("umount", "/proc/fs/nfsd")
	if out, err := cmd.CombinedOutput(); err != nil {
		glog.Errorf("umount nfsd failed with error: %v, output: %v", err, out)
	}

	cmd = exec.Command("echo", ">", "/etc/exports")
	if err := cmd.Run(); err != nil {
		glog.Errorf("Cleaning /etc/exports failed: %v", err)
	}

	glog.Info("Stopped NFS")
}
