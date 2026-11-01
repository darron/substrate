// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package steps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"go.ate.dev/substrate/cmd/ate-setup/internal/config"
	"go.ate.dev/substrate/cmd/ate-setup/internal/images"
	"go.ate.dev/substrate/cmd/ate-setup/internal/kube"
)

// The deploy steps refer to the provider's objects by name. This checks those
// names against the manifests, so a rename fails here rather than in the next
// install.
func TestK8sCredentialProviderManifestsAgree(t *testing.T) {
	e := &Env{Cfg: &config.Config{Root: repoRoot(t)}}

	provider, err := kube.LoadPath(e.k8sCredentialProviderPath(k8sCredentialProviderManifest))
	if err != nil {
		t.Fatalf("loading the provider manifest: %v", err)
	}
	dep := findObject(provider, "Deployment", k8sCredentialProviderDeployment)
	if dep == nil {
		t.Fatalf("provider manifest has no deployment/%s", k8sCredentialProviderDeployment)
	}
	if ns := dep.GetNamespace(); ns != NamespaceAteSystem {
		t.Errorf("deployment/%s is in namespace %q, want %q", k8sCredentialProviderDeployment, ns, NamespaceAteSystem)
	}
	if findObject(provider, "ConfigMap", k8sCredentialProviderPolicyConfigMap) != nil {
		t.Errorf("provider manifest carries configmap/%s itself; the deploy step must own whether it is applied", k8sCredentialProviderPolicyConfigMap)
	}
	if got := mountedConfigMaps(dep); len(got) != 1 || got[0] != k8sCredentialProviderPolicyConfigMap {
		t.Errorf("deployment/%s mounts ConfigMaps %v, want only %q", k8sCredentialProviderDeployment, got, k8sCredentialProviderPolicyConfigMap)
	}
	svc := findObject(provider, "Service", k8sCredentialProviderDeployment)
	if svc == nil {
		t.Fatalf("provider manifest has no service/%s", k8sCredentialProviderDeployment)
	}
	if want := svc.GetName() + "." + svc.GetNamespace() + ".svc:50051"; want != config.K8sCredentialProviderAddress {
		t.Errorf("config.K8sCredentialProviderAddress = %q, but the Service resolves to %q", config.K8sCredentialProviderAddress, want)
	}

	policy, err := kube.LoadPath(e.k8sCredentialProviderPath(k8sCredentialProviderPolicyManifest))
	if err != nil {
		t.Fatalf("loading the policy manifest: %v", err)
	}
	cm := findObject(policy, "ConfigMap", k8sCredentialProviderPolicyConfigMap)
	if cm == nil {
		t.Fatalf("policy manifest has no configmap/%s", k8sCredentialProviderPolicyConfigMap)
	}
	if ns := cm.GetNamespace(); ns != NamespaceAteSystem {
		t.Errorf("configmap/%s is in namespace %q, want %q", k8sCredentialProviderPolicyConfigMap, ns, NamespaceAteSystem)
	}
}

// The provider's NetworkPolicy must select the provider pods and admit only
// the egress gateway's pods, on the port the provider serves gRPC on. The
// labels and the port are read from the manifests, so a rename on either side
// fails here instead of cutting the gateway off from the provider.
func TestK8sCredentialProviderNetworkPolicy(t *testing.T) {
	e := &Env{Cfg: &config.Config{Root: repoRoot(t)}}

	provider, err := kube.LoadPath(e.k8sCredentialProviderPath(k8sCredentialProviderManifest))
	if err != nil {
		t.Fatalf("loading the provider manifest: %v", err)
	}
	dep := findObject(provider, "Deployment", k8sCredentialProviderDeployment)
	if dep == nil {
		t.Fatalf("provider manifest has no deployment/%s", k8sCredentialProviderDeployment)
	}
	np := findObject(provider, "NetworkPolicy", k8sCredentialProviderDeployment)
	if np == nil {
		t.Fatalf("provider manifest has no networkpolicy/%s", k8sCredentialProviderDeployment)
	}
	if ns := np.GetNamespace(); ns != NamespaceAteSystem {
		t.Errorf("networkpolicy/%s is in namespace %q, want %q", np.GetName(), ns, NamespaceAteSystem)
	}

	selector, _, _ := unstructured.NestedStringMap(np.Object, "spec", "podSelector", "matchLabels")
	if !selects(selector, podLabels(dep)) {
		t.Errorf("networkpolicy podSelector %v does not select the provider pods %v", selector, podLabels(dep))
	}
	if types, _, _ := unstructured.NestedStringSlice(np.Object, "spec", "policyTypes"); len(types) != 1 || types[0] != "Ingress" {
		t.Errorf("networkpolicy policyTypes = %v, want [Ingress]", types)
	}

	ingress, _, _ := unstructured.NestedSlice(np.Object, "spec", "ingress")
	if len(ingress) != 1 {
		t.Fatalf("networkpolicy has %d ingress rules, want 1", len(ingress))
	}
	rule := ingress[0].(map[string]any)

	egressObjs, err := kube.LoadPath(e.Cfg.Manifest("atenet-egress.yaml"))
	if err != nil {
		t.Fatalf("loading the egress manifest: %v", err)
	}
	gateway := findObject(egressObjs, "Deployment", "atenet-egress")
	if gateway == nil {
		t.Fatal("egress manifest has no deployment/atenet-egress")
	}
	if gateway.GetNamespace() != np.GetNamespace() {
		t.Errorf("deployment/atenet-egress is in namespace %q, but the networkpolicy only admits pods from %q", gateway.GetNamespace(), np.GetNamespace())
	}
	from, _, _ := unstructured.NestedSlice(rule, "from")
	if len(from) != 1 {
		t.Fatalf("networkpolicy ingress rule has %d peers, want only the egress gateway", len(from))
	}
	peer := from[0].(map[string]any)
	if len(peer) != 1 {
		t.Errorf("networkpolicy peer %v, want a podSelector alone", peer)
	}
	if peerLabels, _, _ := unstructured.NestedStringMap(peer, "podSelector", "matchLabels"); len(peerLabels) == 0 || !selects(peerLabels, podLabels(gateway)) {
		t.Errorf("networkpolicy peer selector %v does not select the egress gateway pods %v", peerLabels, podLabels(gateway))
	}

	ports, _, _ := unstructured.NestedSlice(rule, "ports")
	want := containerPort(t, dep, "grpc")
	if len(ports) != 1 {
		t.Fatalf("networkpolicy admits %d ports, want only grpc (%d)", len(ports), want)
	}
	port := ports[0].(map[string]any)
	if n, ok := asInt(port["port"]); port["protocol"] != "TCP" || !ok || n != want {
		t.Errorf("networkpolicy admits %v/%v, want TCP/%d", port["protocol"], port["port"], want)
	}
}

// podLabels returns the labels of a Deployment's pod template.
func podLabels(dep *unstructured.Unstructured) map[string]string {
	labels, _, _ := unstructured.NestedStringMap(dep.Object, "spec", "template", "metadata", "labels")
	return labels
}

// selects reports whether a matchLabels selector matches labels.
func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

// containerPort returns the number of a Deployment's named container port.
func containerPort(t *testing.T, dep *unstructured.Unstructured, name string) int64 {
	t.Helper()
	containers, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "containers")
	for _, c := range containers {
		ports, _, _ := unstructured.NestedSlice(c.(map[string]any), "ports")
		for _, p := range ports {
			if p.(map[string]any)["name"] == name {
				n, ok := asInt(p.(map[string]any)["containerPort"])
				if !ok {
					t.Fatalf("deployment/%s port %q has no numeric containerPort", dep.GetName(), name)
				}
				return n
			}
		}
	}
	t.Fatalf("deployment/%s has no container port named %q", dep.GetName(), name)
	return 0
}

// asInt reads a decoded manifest number, which may arrive as either an integer
// or a float.
func asInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), n == float64(int64(n))
	}
	return 0, false
}

// mountedConfigMaps returns the names of the ConfigMaps a Deployment's pod
// mounts as volumes.
func mountedConfigMaps(dep *unstructured.Unstructured) []string {
	volumes, _, _ := unstructured.NestedSlice(dep.Object, "spec", "template", "spec", "volumes")
	var names []string
	for _, v := range volumes {
		name, found, _ := unstructured.NestedString(v.(map[string]any), "configMap", "name")
		if found {
			names = append(names, name)
		}
	}
	return names
}

func TestRemoveK8sCredentialProviderPreservesCredentials(t *testing.T) {
	ctx := t.Context()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "trial-secrets"}}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "operator-credential", Namespace: ns.Name}, Data: map[string][]byte{"token": []byte("preserve")}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: k8sCredentialProviderDeployment, Namespace: NamespaceAteSystem}}
	legacy := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: k8sCredentialProviderLegacyBinding}}
	k, dc := fakeDeleteKube(t, []runtime.Object{dep, legacy}, []runtime.Object{ns, secret})
	cs := k.Typed.(*fake.Clientset)
	cs.Fake.Resources[0].APIResources = append(cs.Fake.Resources[0].APIResources,
		metav1.APIResource{Name: "namespaces", Kind: "Namespace"},
		metav1.APIResource{Name: "secrets", Kind: "Secret", Namespaced: true},
		metav1.APIResource{Name: "services", Kind: "Service", Namespaced: true})
	e := &Env{Cfg: &config.Config{Root: repoRoot(t)}, Kube: k}
	if err := e.removeK8sCredentialProvider(ctx); err != nil {
		t.Fatal(err)
	}
	for _, action := range dc.Actions() {
		if action.GetVerb() == "delete" && (action.GetResource().Resource == "namespaces" || action.GetResource().Resource == "secrets") {
			t.Fatalf("provider removal deletes credentials: %v", action)
		}
	}
	got, err := dc.Resource(schema.GroupVersionResource{Version: "v1", Resource: "secrets"}).Namespace(ns.Name).Get(ctx, secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if data, _, _ := unstructured.NestedStringMap(got.Object, "data"); data["token"] != "cHJlc2VydmU=" {
		t.Fatalf("credential changed: %v", data)
	}
	if _, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, legacy.Name, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("legacy grant remains: %v", err)
	}
}

func TestRemoveLegacyCredentialProviderBinding(t *testing.T) {
	for _, tc := range []struct {
		name            string
		present, denied bool
	}{
		{name: "existing", present: true}, {name: "absent"}, {name: "forbidden", present: true, denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var objs []runtime.Object
			if tc.present {
				objs = append(objs, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: k8sCredentialProviderLegacyBinding}})
			}
			e := &Env{Kube: fakeKube(t, objs...)}
			if tc.denied {
				e.Kube.Typed.(*fake.Clientset).PrependReactor("delete", "clusterrolebindings", func(clienttesting.Action) (bool, runtime.Object, error) {
					return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, k8sCredentialProviderLegacyBinding, errors.New("denied"))
				})
			}
			if err := e.removeLegacyCredentialProviderBinding(t.Context()); (err != nil) != tc.denied {
				t.Fatalf("error = %v, denied = %v", err, tc.denied)
			}
		})
	}
}

func TestDeployK8sCredentialProviderReplacesLegacyGrant(t *testing.T) {
	for _, failApply := range []bool{false, true} {
		t.Run(fmt.Sprint("applyFailure=", failApply), func(t *testing.T) {
			legacy := &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: k8sCredentialProviderLegacyBinding}}
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: k8sCredentialProviderPolicyConfigMap, Namespace: NamespaceAteSystem}}
			k, dc := fakeDeleteKube(t, []runtime.Object{legacy, cm}, nil)
			k.Typed.(*fake.Clientset).Fake.Resources[0].APIResources = append(k.Typed.(*fake.Clientset).Fake.Resources[0].APIResources, metav1.APIResource{Name: "namespaces", Kind: "Namespace"}, metav1.APIResource{Name: "services", Kind: "Service", Namespaced: true})
			appliedBinding := false
			dc.PrependReactor("patch", "*", func(action clienttesting.Action) (bool, runtime.Object, error) {
				patch := action.(clienttesting.PatchAction)
				obj := &unstructured.Unstructured{}
				if err := json.Unmarshal(patch.GetPatch(), &obj.Object); err != nil {
					t.Fatal(err)
				}
				if obj.GetKind() == "RoleBinding" {
					if failApply {
						return true, nil, apierrors.NewBadRequest("replacement failed")
					}
					appliedBinding = true
				}
				return true, obj, nil
			})
			k.Typed.(*fake.Clientset).PrependReactor("delete", "clusterrolebindings", func(action clienttesting.Action) (bool, runtime.Object, error) {
				if !appliedBinding {
					t.Fatal("legacy grant removed before replacement applied")
				}
				return false, nil, nil
			})
			src := images.Source{Repo: "example.com/substrate", Tag: "candidate"}
			e := &Env{Cfg: &config.Config{Root: repoRoot(t)}, Kube: k, resolver: images.NewPrebuilt(src, func(context.Context, string) (string, error) { return "sha256:" + strings.Repeat("a", 64), nil })}
			if err := e.deployK8sCredentialProvider(t.Context()); (err != nil) != failApply {
				t.Fatalf("error = %v, failed apply = %v", err, failApply)
			}
			_, err := k.Typed.RbacV1().ClusterRoleBindings().Get(t.Context(), legacy.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) == failApply {
				t.Fatalf("legacy binding state incorrect after deploy: %v", err)
			}
		})
	}
}

func TestDeleteCredentialProviderRemovesLegacyGrantFirst(t *testing.T) {
	for _, entry := range []struct {
		name string
		run  func(*Env) error
	}{
		{"ate-system", func(e *Env) error { return e.DeleteAteSystem(t.Context()) }},
		{"atenet", func(e *Env) error { return e.DeleteAtenet(t.Context()) }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			e := &Env{Cfg: &config.Config{Root: repoRoot(t)}, Kube: fakeKube(t)}
			denied := apierrors.NewForbidden(schema.GroupResource{Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, k8sCredentialProviderLegacyBinding, errors.New("denied"))
			e.Kube.Typed.(*fake.Clientset).PrependReactor("delete", "clusterrolebindings", func(clienttesting.Action) (bool, runtime.Object, error) { return true, nil, denied })
			if err := entry.run(e); !errors.Is(err, denied) {
				t.Fatalf("delete must surface legacy grant cleanup error before other teardown: %v", err)
			}
		})
	}
}
