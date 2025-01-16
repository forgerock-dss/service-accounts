#!/bin/bash

# Script to create a Service Account in ID Cloud, mint access tokens using it and make examples calls to IDM and AM
# Written by Darinder S Shokar - ForgeRock Professional Services
# Script requires "OpenSSL", "jq" and "jose" tools be installed on the system to function
# Tested on MacOS only

# Parameters to modify:
TENANT="openam-<tenant>.forgerock.io"
SERVICE_ACCOUNT_NAME="new_service_account"
SERVICE_ACCOUNT_DESCRIPTION="A service account to interact with the IDM AM and ESVs"
SERVICE_ACCOUNT_SCOPES='["fr:am:*","fr:idm:*","fr:idc:esv:*"]'
SERVICE_ACCOUNT_ID_FILE="./account_id.txt"
SERVICE_REQUEST_JWT="./payload.json"
SERVICE_REQUEST_SIGNED_JWT="./jwt.txt"
REALM="alpha"

# No need to modify these parameters:
HOST_URL=https://${TENANT}
IDM_ENDPOINT="https://${TENANT}/openidm/managed/${REALM}_user?_fields=userName,givenName,sn,mail,accountStatus&_prettyPrint=true&_queryFilter=true&_pageSize=1"
AM_ENDPOINT="https://${TENANT}/am/json/realms/root/realms/${REALM}/realm-config/services/validation"
AUD=${HOST_URL}:443/am/oauth2/access_token
SERVICE_ACCOUNT_URL="https://${TENANT}/openidm/managed/svcacct?_action=create"
SERVICE_ACCOUNT_CHANGE_URL="https://${TENANT}/openidm/managed/svcacct" 
FORMATTED_SCOPES=$(echo ${SERVICE_ACCOUNT_SCOPES} | tr -d \"\[\] | sed s,"\,"," ",g)
PRIVATE_KEY_JWK=${TENANT}.jwk
EXP=$(($(date -u +%s) + 180))
JTI=$(openssl rand -base64 16)
ADMIN_BEARER_TOKEN=$1

# Check if openssl is installed, exits if not
opensslCheck() {
	hash openssl &>/dev/null
	if [ $? -eq 1 ]; then
		echo >&2 "OpenSSL is not installed on the system.Please install and re-run"
		exit 1
	fi

}

# Checks if jq is installed, exits if not
jqCheck() {
	hash jq &>/dev/null
	if [ $? -eq 1 ]; then
		echo >&2 "The jq Command-line JSON processor is not installed on the system. Please install and re-run."
		exit 1
	fi
}

# Checks if jose is installed, exits if not
joseCheck() {
	hash jose &>/dev/null
	if [ $? -eq 1 ]; then
		echo >&2 "Jose is not installed on the system.Please install from here and re-run: https://command-not-found.com/jose"
		exit 1
	fi
}

# Creates a Service Account and associated key and config material
createServiceAccount() {
	echo "------------------------------------------"
	if [ -z "${ADMIN_BEARER_TOKEN}" ]; then
		echo "No Bearer Token supplied. Acquire an admin bearer token for the environment and then execute using ./service_accounts.sh eyJ0eXAiOiJKV..."
		exit 1
	fi
	echo "Creating new service account called: ${SERVICE_ACCOUNT_NAME}"
	jose jwk gen -i '{"alg": "RS256"}' -o ${PRIVATE_KEY_JWK}
	cat ${PRIVATE_KEY_JWK} | jq -c 'del(.alg,.key_ops)' >${PRIVATE_KEY_JWK}.2
	mv ${PRIVATE_KEY_JWK}.2 ${PRIVATE_KEY_JWK}
	chmod 600 ${PRIVATE_KEY_JWK}
	echo "Service account private key JWK created called ${PRIVATE_KEY_JWK}"
	JWK=$(cat ${PRIVATE_KEY_JWK} | jq -c 'del(.d,.dq,.dp,.p,.q,.qi)')
	JWK_ESCAPED=$(echo ${JWK} | sed 's/"/\\"/g')
	POST_DATA='{"name":"'${SERVICE_ACCOUNT_NAME}'","description":"'${SERVICE_ACCOUNT_DESCRIPTION}'","scopes":'${SERVICE_ACCOUNT_SCOPES}',"jwks":"'{'\"keys\":['${JWK_ESCAPED}']}"}'
	echo "Creating ${SERVICE_ACCOUNT_NAME} in tenant ${TENANT}"
	SERVICE_ACCOUNT_RESPONSE=$(curl -s --request POST \
		--header 'content-type: application/json' \
		--header 'Authorization: Bearer '${ADMIN_BEARER_TOKEN}'' \
		--data-raw "${POST_DATA}" \
		"${SERVICE_ACCOUNT_URL}")
	echo ${SERVICE_ACCOUNT_RESPONSE} | jq .
	SERVICE_ACCOUNT_ID=$(echo ${SERVICE_ACCOUNT_RESPONSE} | jq -r ."_id" >${SERVICE_ACCOUNT_ID_FILE})
	chmod 600 ${SERVICE_ACCOUNT_ID_FILE}
	echo "Service Account _id value is:"
	cat ${SERVICE_ACCOUNT_ID_FILE}
}

# Creates an access token using the Service Account and signed JWT
getAccessToken() {
	echo "------------------------------------------"
	if [ ! -f "${SERVICE_ACCOUNT_ID_FILE}" ]; then
		echo "${SERVICE_ACCOUNT_ID_FILE} file does not exist. Run the createServiceAccount function"
		exit 1
	else
		SERVICE_ACCOUNT_ID=$(cat ${SERVICE_ACCOUNT_ID_FILE})
	fi
	if [ ! -f "${PRIVATE_KEY_JWK}" ]; then
		echo "${PRIVATE_KEY_JWK} file does not exist. Run the createServiceAccount function"
		exit 1
	else
		SERVICE_ACCOUNT_ID=$(cat ${SERVICE_ACCOUNT_ID_FILE})
	fi
	echo "Creating JWT for service account with _id value: ${SERVICE_ACCOUNT_ID}"
	echo -n "{
	\"iss\":\"${SERVICE_ACCOUNT_ID}\",
	\"sub\":\"${SERVICE_ACCOUNT_ID}\",
	\"aud\":\"${AUD}\",
	\"exp\":${EXP},
	\"jti\":\"${JTI}\"
	}" >${SERVICE_REQUEST_JWT}
	echo "Signing JWT with private key from ${PRIVATE_KEY_JWK}"
	jose jws sig -I ${SERVICE_REQUEST_JWT} -k ${PRIVATE_KEY_JWK} -s '{"alg":"RS256"}' -c -o ${SERVICE_REQUEST_SIGNED_JWT}
	echo "Generating access token from signed JWT"
	ACCESS_TOKEN_OUTPUT=$(curl -s \
		--request POST ${AUD} \
		--data "client_id=service-account" \
		--data "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
		--data "assertion=$(<${SERVICE_REQUEST_SIGNED_JWT})" \
		--data "scope=${FORMATTED_SCOPES}")
	echo "Access token is:"
	echo ${ACCESS_TOKEN_OUTPUT} | jq .
	ACCESS_TOKEN=$(echo ${ACCESS_TOKEN_OUTPUT} | jq -r .access_token)
	rm ${SERVICE_REQUEST_JWT} ${SERVICE_REQUEST_SIGNED_JWT}
}

# Call an IDM API using a Service Account access token
callIDM() {
	echo "------------------------------------------"
	echo "Calling this IDM Endpoint: ${IDM_ENDPOINT} in realm: ${REALM} using access token:"
	echo ${ACCESS_TOKEN}
	curl -s \
		--request GET \
		--header 'Authorization: Bearer '${ACCESS_TOKEN}'' \
		${IDM_ENDPOINT} | jq .

}

# Call am AM API using a Service Account acess token
callAM() {
	echo "------------------------------------------"
	echo "Calling this AM Endpoint: ${AM_ENDPOINT} in realm: ${REALM} using access token:"
	echo ${ACCESS_TOKEN}
	curl -s \
		--request GET \
		--header 'Authorization: Bearer '${ACCESS_TOKEN}'' \
		${AM_ENDPOINT} | jq .
}

# Regenerates the key for a given Service Account
changeKeyforServiceAccount() {
	echo "------------------------------------------"
	if [ -z "${ADMIN_BEARER_TOKEN}" ]; then
		echo "No Bearer Token supplied. Acquire an admin bearer for the environment and then execute using ./service_accounts.sh eyJ0eXAiOiJKV..."
		exit 1
	fi
	
	#Set _id and URL for modification
	EXISTING_SERVICE_ACCOUNT_ID=`cat ${SERVICE_ACCOUNT_ID_FILE}`
	SERVICE_ACCOUNT_CHANGE_URL_WITH_ID="${SERVICE_ACCOUNT_CHANGE_URL}/${EXISTING_SERVICE_ACCOUNT_ID}"

	echo "Regenerating key for service account called: ${SERVICE_ACCOUNT_NAME}"
	jose jwk gen -i '{"alg": "RS256"}' -o ${PRIVATE_KEY_JWK}
	cat ${PRIVATE_KEY_JWK} | jq -c 'del(.alg,.key_ops)' >${PRIVATE_KEY_JWK}.2
	mv ${PRIVATE_KEY_JWK}.2 ${PRIVATE_KEY_JWK}
	chmod 600 ${PRIVATE_KEY_JWK}
	echo "Service account private key JWK created called ${PRIVATE_KEY_JWK}"
	JWK=$(cat ${PRIVATE_KEY_JWK} | jq -c 'del(.d,.dq,.dp,.p,.q,.qi)')
	JWK_ESCAPED=$(echo ${JWK} | sed 's/"/\\"/g')
	PUT_DATA='{"name":"'${SERVICE_ACCOUNT_NAME}'","description":"'${SERVICE_ACCOUNT_DESCRIPTION}'","scopes":'${SERVICE_ACCOUNT_SCOPES}',"accountStatus":"active","jwks":"'{'\"keys\":['${JWK_ESCAPED}']}"}'
	echo "Modifying ${SERVICE_ACCOUNT_NAME} in tenant ${TENANT}"
	SERVICE_ACCOUNT_RESPONSE=$(curl -s --request PUT \
		--header 'content-type: application/json' \
		--header 'Authorization: Bearer '${ADMIN_BEARER_TOKEN}'' \
		--data-raw "${PUT_DATA}" \
		"${SERVICE_ACCOUNT_CHANGE_URL_WITH_ID}")
	echo ${SERVICE_ACCOUNT_RESPONSE} | jq .
}

#Functions
clear
opensslCheck
jqCheck
joseCheck
createServiceAccount #Comment out if you don't want to create a new service account for every execution of this script
getAccessToken
callIDM #Modify IDM_ENDPOINT to target a different IDM endpoint
callAM  #Modify AM_ENDPOINT to target a different AM endpoint
#changeKeyforServiceAccount #Use to regenerate the service account private key and update the service account in P1AIC
