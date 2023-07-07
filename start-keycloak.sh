#!/bin/bash
echo "* Starting Keycloak !"
docker compose up -d
sleep 100
echo "* Keycloak Started !"
echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Luke user creation\n"
curl --location --request POST 'http://localhost:8080/admin/realms/test/users' -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '{ "createdTimestamp": 1588880747548, "username": "luke", "enabled": true, "totp": false, "emailVerified": false, "firstName": "Luke", "lastName": "Skywalker", "email": "luke.skywalker@jedi.com", "credentials":[{"type":"password","value":"password","temporary":false}], "disableableCredentialTypes": [], "requiredActions": [], "notBefore": 0, "access": { "manageGroupMembership": true, "view": true, "mapRoles": true, "impersonate": true, "manage": true }}'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Darth user creation\n"
curl --location --request POST 'http://localhost:8080/admin/realms/test/users' -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '{ "createdTimestamp": 1588880747548, "username": "darth", "enabled": true, "totp": false, "emailVerified": false, "firstName": "Darth", "lastName": "Wader", "email": "darth.wader@jedi.com", "credentials":[{"type":"password","value":"password","temporary":false}], "disableableCredentialTypes": [], "requiredActions": [], "notBefore": 0, "access": { "manageGroupMembership": true, "view": true, "mapRoles": true, "impersonate": true, "manage": true }}'
echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

ids=$(curl -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" "http://localhost:8080/admin/realms/test/users" | jq -r '.[].id')
echo "$ids"

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

id=($ids)
echo ${id[1]}

echo "\n"
echo " * map role app_user to luke user\n"
curl --location --request POST "http://localhost:8080/admin/realms/test/users/${id[1]}/role-mappings/realm" -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '[{ "id": "81c338bb-48db-42e4-a97e-d4bd5845859a", "name": "app_user"}]'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * map role app_admin to darth user\n"
curl --location --request POST "http://localhost:8080/admin/realms/test/users/${id[0]}/role-mappings/realm" -H "Content-Type: application/json" -H "Authorization: bearer $TOKEN" --data '[{ "id": "6e66c979-0820-463b-877d-6556521b02c9", "name": "app_admin"}]'

echo "\n"
echo "* Request for authorization\n"
RESULT=`curl --data "username=admin&password=admin&grant_type=password&client_id=admin-cli" http://localhost:8080/realms/master/protocol/openid-connect/token`

echo "\n"
echo "* Recovery of the token\n"
TOKEN=`echo $RESULT | sed 's/.*access_token":"//g' | sed 's/".*//g'`

echo "\n"
echo "* Display token\n"
echo $TOKEN

echo "\n"
echo " * Get users \n"
curl http://localhost:8080/admin/realms/test/users -H "Authorization: bearer $TOKEN"
