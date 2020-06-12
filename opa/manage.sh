#!/usr/bin/env bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function remove_certs {
    echo -e "${GREEN}[-] Removing certificates...${NC}"
    if [[ -f "ca.crt" ]] && [[ -f "ca.key" ]] && [[ -f "ca.srl" ]]; then
        rm -f ca.crt ca.key ca.srl
    fi

    if [[ -f "server.conf" ]] && [[ -f "server.crt" ]] && [[ -f "server.csr" ]] && [[ -f "server.key" ]]; then
        rm -f server.conf server.crt server.csr server.key
    fi
}

function install {
    echo -e "${GREEN}[+] Installing...${NC}"
    echo -e "${GREEN}[+] Creating opa namespace...${NC}"
    kubectl apply -f namespace.yaml

    echo -e "${GREEN}[+] Generating CA certificate...${NC}"
    remove_certs
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -nodes -key ca.key -days 100000 -out ca.crt -subj "/CN=admission_ca"

    cat >server.conf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, serverAuth
EOF

    echo -e "${GREEN}[+] Generating server certificate...${NC}"
    openssl genrsa -out server.key 2048
    openssl req -new -key server.key -out server.csr -subj "/CN=opa.opa.svc" -config server.conf
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 100000 -extensions v3_req -extfile server.conf

    echo -e "${GREEN}[+] Creating Kubernetes secret...${NC}"
    kubectl -n opa create secret tls opa-server --cert=server.crt --key=server.key
    #kubectl -n opa apply -f secret.yaml

    echo -e "${GREEN}[+] Creating OPA admission controller...${NC}"
    kubectl -n opa apply -f admission-controller.yaml

    echo -e "${GREEN}[+] Labelling namespaces...${NC}"
    declare -a namespaces=("kube-system" "opa")
    for ns in "${namespaces[@]}"; do
        echo -e "${YELLOW}[+] Namespace: ${ns}${NC}"
        LABEL=$(kubectl get ns "${ns}" --show-labels | awk 'FNR == 2 {print $4}')
        if ! [[ "${LABEL}" == "openpolicyagent.org/webhook=ignore" ]]; then
            kubectl label ns "${ns}" openpolicyagent.org/webhook=ignore
        else
            echo -e "${YELLOW}[+] Label already present on ${ns} namespace.${NC}"
        fi
    done

    echo -e "${GREEN}[+] Creating Kubernetes OPA webhook...${NC}"
    kubectl -n opa apply -f webhook-configuration.yaml

    echo -e "${GREEN}[+] Done!${NC}"
}

function uninstall {
    echo -e "${GREEN}[-] Uninstalling...${NC}"
    remove_certs
    echo -e "${GREEN}[-] Deleting Kubernetes objects...${NC}"
    kubectl delete -f ../nginx/
    kubectl -n opa delete -f .
    kubectl -n opa delete secret opa-server
    echo -e "${GREEN}[-] Removing namespace labels...${NC}"
    echo -e "${YELLOW}[-] Namespace: kube-system${NC}"
    LABEL=$(kubectl get ns kube-system --show-labels | awk 'FNR == 2 {print $4}')
    if [[ "${LABEL}" == "openpolicyagent.org/webhook=ignore" ]]; then
        kubectl label ns kube-system openpolicyagent.org/webhook-
    else
        echo -e "${YELLOW}[-] Label already absent on kube-system namespace.${NC}"
    fi
}

case $1 in
    "install")
        pushd opa || exit 1
        install
        popd > /dev/null || exit 1
        ;;
    "uninstall")
        pushd opa || exit 1
        uninstall
        popd > /dev/null || exit 1
        ;;
    *)
        echo -e "${RED} [!] Usage: install.sh install|uninstall${NC}"
        exit 1
esac

