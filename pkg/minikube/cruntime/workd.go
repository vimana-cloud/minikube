/*
Copyright 2024 Vimana All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cruntime

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"time"

	"github.com/blang/semver/v4"
	"github.com/pkg/errors"
	"k8s.io/klog/v2"
	"k8s.io/minikube/pkg/minikube/assets"
	"k8s.io/minikube/pkg/minikube/bootstrapper/images"
	"k8s.io/minikube/pkg/minikube/command"
	"k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/download"
	"k8s.io/minikube/pkg/minikube/style"
	"k8s.io/minikube/pkg/minikube/sysinit"
)

// Workd contains Vimana runtime state.
type Workd struct {
	Socket string
	Runner CommandRunner
	//ImageRepository   string
	KubernetesVersion semver.Version
	Init              sysinit.Manager
}

// Name is a human readable name for the runtime.
func (r *Workd) Name() string {
	klog.Infof("Workd.Name()")
	return "workd"
}

// Style is the console style for Vimana.
func (r *Workd) Style() style.Enum {
	klog.Infof("Workd.Style()")
	return style.Workd
}

// Version retrieves the current version of this runtime.
func (r *Workd) Version() (string, error) {
	klog.Infof("Workd.Version()")
	c := exec.Command("workd", "--version")
	rr, err := r.Runner.RunCmd(c)
	if err != nil {
		return "", errors.Wrap(err, "workd --version")
	}
	return rr.Stdout.String(), nil
}

// SocketPath returns the path to the socket file for the Vimana work runtime.
func (r *Workd) SocketPath() string {
	klog.Infof("Workd.SocketPath()")
	if r.Socket != "" {
		return r.Socket
	}
	return "/run/vimana/workd.sock"
}

// Available returns an error if it is not possible to use this runtime on a host.
func (r *Workd) Available() error {
	klog.Infof("Workd.Available()")
	c := exec.Command("which", "workd")
	if _, err := r.Runner.RunCmd(c); err != nil {
		return errors.Wrapf(err, "check workd available")
	}
	// TODO: Determine if we actually need CNI plugins.
	return checkCNIPlugins(r.KubernetesVersion)
}

// Active returns if the Vimana work runtime is active on the host.
func (r *Workd) Active() bool {
	klog.Infof("Workd.Active()")
	return r.Init.Active("workd")
}

// Enable idempotently enables the Vimana work runtime on a host.
func (r *Workd) Enable(disOthers bool, cgroupDriver string, inUserNamespace bool) error {
	klog.Infof("Workd.Enable(%#v, %#v, %#v)", disOthers, cgroupDriver, inUserNamespace)

	if disOthers {
		if err := disableOthers(r, r.Runner); err != nil {
			klog.Warningf("disableOthers: %v", err)
		}
	}

	// Set up `/etc/crictl.yaml`.
	if err := populateCRIConfig(r.Runner, r.SocketPath()); err != nil {
		return err
	}

	// TODO: Determine if this is necessary.
	if err := enableIPForwarding(r.Runner); err != nil {
		return err
	}

	// TODO: Verify that we never need non-rootless (see CRI-O example).
	return r.Init.Restart("workd")
}

// Disable idempotently disables the runtime on a host.
func (r *Workd) Disable() error {
	klog.Infof("Workd.Disable()")
	return r.Init.ForceStop("workd")
}

// ImageExists checks if image exists based on image name and optionally image hash.
func (r *Workd) ImageExists(name string, sha string) bool {
	klog.Infof("Workd.ImageExists(%#v, %#v)", name, sha)
	// TODO: Figure out how this should work.
	return false
}

// ListImages returns a list of images managed by this container runtime.
func (r *Workd) ListImages(options ListImagesOptions) ([]ListImage, error) {
	klog.Infof("Workd.ListImages(%#v)", options)
	// TODO: Figure out how this should work.
	return []ListImage{}, nil
}

// LoadImage loads an image into this runtime.
func (r *Workd) LoadImage(path string) error {
	klog.Infof("Workd.LoadImage(%#v)", path)
	// TODO: Figure out how this should work.
	return nil
}

// PullImage pulls an image.
func (r *Workd) PullImage(name string) error {
	klog.Infof("Workd.PullImage(%#v)", name)
	// TODO: Figure out how this should work.
	return nil
}

// SaveImage saves an image from this runtime.
func (r *Workd) SaveImage(name string, path string) error {
	klog.Infof("Workd.SaveImage(%#v, %#v)", name, path)
	// TODO: Figure out how this should work.
	return nil
}

// RemoveImage removes a image.
func (r *Workd) RemoveImage(name string) error {
	klog.Infof("Workd.RemoveImage(%#v)", name)
	// TODO: Figure out how this should work.
	return nil
}

// TagImage tags an image in this runtime.
func (r *Workd) TagImage(source string, target string) error {
	klog.Infof("Workd.RemoveImage(%#v, %#v)", source, target)
	// TODO: Figure out how this should work.
	return nil
}

// BuildImage builds an image into this runtime.
func (r *Workd) BuildImage(src string, file string, tag string, push bool, env []string, opts []string) error {
	klog.Infof("Workd.BuildImage(%#v, %#v, %#v, %#v, %#v, %#v)", src, file, tag, push, env, opts)
	return nil
}

// PushImage pushes an image.
func (r *Workd) PushImage(name string) error {
	klog.Infof("Workd.PushImage(%#v)", name)
	return nil
}

// CGroupDriver returns cgroup driver ("cgroupfs" or "systemd").
func (r *Workd) CGroupDriver() (string, error) {
	klog.Infof("Workd.CGroupDriver()")
	// Vimana does not use cgroups to manage container resources.
	// These are managed by the Wasm runtime.
	// Return an unexpected value here just to see if anything breaks.
	return "wasmtime", nil
}

// KubeletOptions returns kubelet options for a runtime.
func (r *Workd) KubeletOptions() map[string]string {
	klog.Infof("Workd.KubeletOptions()")
	// Copied from [kubeletCRIOptions].
	opts := map[string]string{
		"container-runtime-endpoint": fmt.Sprintf("unix://%s", r.SocketPath()),
	}
	if r.KubernetesVersion.LT(semver.MustParse("1.24.0-alpha.0")) {
		opts["container-runtime"] = "remote"
	}
	return opts
}

// ListContainers returns a list of containers managed by this runtime.
func (r *Workd) ListContainers(options ListContainersOptions) ([]string, error) {
	klog.Infof("Workd.ListContainers(%#v)", options)
	// Invoked to check on kube-system containers, so use the containerd namespace root.
	return listCRIContainers(r.Runner, containerdNamespaceRoot, options)
}

// PauseContainers pauses a running container based on ID.
func (r *Workd) PauseContainers(ids []string) error {
	klog.Infof("Workd.PauseContainers(%#v)", ids)
	// Invoked to check on kube-system containers, so use the containerd namespace root.
	return pauseCRIContainers(r.Runner, containerdNamespaceRoot, ids)
}

// UnpauseContainers unpauses a running container based on ID.
func (r *Workd) UnpauseContainers(ids []string) error {
	klog.Infof("Workd.UnpauseContainers(%#v)", ids)
	// Invoked to check on kube-system containers, so use the containerd namespace root.
	return unpauseCRIContainers(r.Runner, containerdNamespaceRoot, ids)
}

// KillContainers removes containers based on ID.
func (r *Workd) KillContainers(ids []string) error {
	klog.Infof("Workd.KillContainers(%#v)", ids)
	return killCRIContainers(r.Runner, ids)
}

// StopContainers stops containers based on ID.
func (r *Workd) StopContainers(ids []string) error {
	klog.Infof("Workd.StopContainers(%#v)", ids)
	return stopCRIContainers(r.Runner, ids)
}

// ContainerLogCmd returns the command to retrieve the log for a container based on ID.
func (r *Workd) ContainerLogCmd(id string, length int, follow bool) string {
	klog.Infof("Workd.ContainerLogCmd(%#v, %#v, %#v)", id, length, follow)
	return criContainerLogCmd(r.Runner, id, length, follow)
}

// SystemLogCmd returns the command to retrieve system logs.
func (r *Workd) SystemLogCmd(length int) string {
	klog.Infof("Workd.SystemLogCmd(%#v)", length)
	return fmt.Sprintf("sudo journalctl -u workd -n %d", length)
}

// Preload preloads the container runtime with k8s images
func (r *Workd) Preload(cc config.ClusterConfig) error {
	klog.Infof("Workd.Preload(%#v)", cc)

	k8sVersion := cc.KubernetesConfig.KubernetesVersion
	cRuntime := cc.KubernetesConfig.ContainerRuntime

	if !download.PreloadExists(k8sVersion, cRuntime, cc.Driver) {
		return nil
	}

	// If images already exist, return
	images, err := images.Kubeadm(cc.KubernetesConfig.ImageRepository, k8sVersion)
	if err != nil {
		return errors.Wrap(err, "getting images")
	}
	if crictlImagesPreloaded(r.Runner, images) {
		klog.Info("Images already preloaded, skipping extraction")
		return nil
	}

	tarballPath := download.TarballPath(k8sVersion, cRuntime)
	targetDir := "/"
	targetName := "preloaded.tar.lz4"
	dest := path.Join(targetDir, targetName)

	c := exec.Command("which", "lz4")
	if _, err := r.Runner.RunCmd(c); err != nil {
		return NewErrISOFeature("lz4")
	}

	// Copy over tarball into host
	fa, err := assets.NewFileAsset(tarballPath, targetDir, targetName, "0644")
	if err != nil {
		return errors.Wrap(err, "getting file asset")
	}
	defer func() {
		if err := fa.Close(); err != nil {
			klog.Warningf("error closing the file %s: %v", fa.GetSourcePath(), err)
		}
	}()

	t := time.Now()
	if err := r.Runner.Copy(fa); err != nil {
		return errors.Wrap(err, "copying file")
	}
	klog.Infof("duration metric: took %s to copy over tarball", time.Since(t))

	t = time.Now()
	// extract the tarball to /var in the VM
	if rr, err := r.Runner.RunCmd(exec.Command("sudo", "tar", "--xattrs", "--xattrs-include", "security.capability", "-I", "lz4", "-C", "/var", "-xf", dest)); err != nil {
		return errors.Wrapf(err, "extracting tarball: %s", rr.Output())
	}
	klog.Infof("duration metric: took %s to extract the tarball", time.Since(t))

	//  remove the tarball in the VM
	if err := r.Runner.Remove(fa); err != nil {
		klog.Infof("error removing tarball: %v", err)
	}

	return nil
}

// crictlImagesPreloaded returns true if all images have been preloaded
func crictlImagesPreloaded(runner command.Runner, images []string) bool {
	// Copied from [crioImagesPreloaded] but with a different error message.
	// These methods should probably be consolidated with [containerdImagesPreloaded].
	rr, err := runner.RunCmd(exec.Command("sudo", "crictl", "images", "--output", "json"))
	if err != nil {
		return false
	}

	var jsonImages crictlImages
	err = json.Unmarshal(rr.Stdout.Bytes(), &jsonImages)
	if err != nil {
		klog.Errorf("failed to unmarshal images, will assume images are not preloaded")
		return false
	}

	// Make sure images == imgs
	for _, i := range images {
		found := false
		for _, ji := range jsonImages.Images {
			for _, rt := range ji.RepoTags {
				i = addRepoTagToImageName(i)
				if i == rt {
					found = true
					break
				}
			}
			if found {
				break
			}

		}
		if !found {
			klog.Infof("couldn't find preloaded image for %q. assuming images are not preloaded.", i)
			return false
		}
	}
	klog.Infof("all images are preloaded for Vimana runtime.")
	return true
}

// ImagesPreloaded returns true if all images have been preloaded.
func (r *Workd) ImagesPreloaded(images []string) bool {
	return crictlImagesPreloaded(r.Runner, images)
}
