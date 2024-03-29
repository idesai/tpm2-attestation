#!/bin/bash

tput sc; read -r -p "Continue?"; tput rc; tput el

# Fixed location
pca_location="$PWD/../PCA"

# Device Location not fixed
device_location=""

# State
event_file_found=0
device_registration_request=0
device_service_request=0

# Attestation Data
GOLDEN_PCR_SELECTION="sha1:0,1,2+sha256:0,1,2"
GOLDEN_PCR="59bf9091f4cbbd2a8796bfe086a501c57226c42739dcf8ad323e7493ad51e38f"

# Service Data
SERVICE_CONTENT="Hello world!"

wait_loop() {
    counter=1
    until [ $counter -gt $1 ]
    do
       test -f $2
       if [ $? == 0 ];then
          event_file_found=1
          break
       else
          echo -ne "Waiting $1 seconds: $counter"'\r'
       fi
       ((counter++))
       sleep 1
    done
}

LOG_ERROR() {
    errorstring=$1
    echo -e "\033[31mFAIL: \e[97m${errorstring}\e[0m"
}

LOG_INFO() {
    messagestring=$1
    echo -e "\033[93mPASS: \e[97m${messagestring}\e[0m"
}

device_registration() {

    REGISTRATION_TOKEN=`dd if=/dev/urandom bs=1 count=32 status=none | \
    xxd -p -c32`

    device_location=`grep device_location d_s_registration.txt | \
    awk '{print $2}'`
    rm -f d_s_registration.txt

    data_to_privacy_ca="
    device_location: $device_location
    registration_token: $REGISTRATION_TOKEN
    "

    echo "$data_to_privacy_ca" > s_p_registration.txt
    cp s_p_registration.txt $pca_location/.
    rm -f s_p_registration.txt

    # Send privacy-CA information to device
    echo "privacy_ca_location: $pca_location" > s_d_registration.txt
    cp s_d_registration.txt $device_location/.
    rm -f s_d_registration.txt

    # Wait for device_registration_token from device
    registration_status_string="Registration-Token reciept from device."
    wait_loop $max_wait d_s_registration_token.txt
    if [ $event_file_found == 0 ];then
      LOG_ERROR "$registration_status_string"
      return 1
    fi
    LOG_INFO "$registration_status_string"
    event_file_found=0
    test_registration_token=`grep registration_token \
    d_s_registration_token.txt | awk '{print $2}'`
    rm -f d_s_registration_token.txt

    registration_status_string="Registration-Token validation"
    if [ $test_registration_token == $REGISTRATION_TOKEN ];then
      LOG_INFO "$registration_status_string"
      return 0
    else
      LOG_ERROR "$registration_status_string"
      return 1
    fi
}

device_node_identity_challenge() {
    SERVICE_TOKEN=`dd if=/dev/urandom bs=1 count=32 status=none | \
    xxd -p -c32`

    device_location=`grep device_location d_s_service.txt | \
    awk '{print $2}'`
    rm -f d_s_service.txt

    data_to_privacy_ca="
    device_location: $device_location
    service_token: $SERVICE_TOKEN
    "

    echo "$data_to_privacy_ca" > s_p_service.txt
    cp s_p_service.txt $pca_location/.
    rm -f s_p_service.txt

    # Send privacy-CA information to device
    echo "privacy_ca_location: $pca_location" > s_d_service.txt
    cp s_d_service.txt $device_location
    rm -f s_d_service.txt

   identity_challenge_status_string="Aborting service request - AIK not found."
   test -f d_s_service_aik.pub
   if [ $? == 1 ];then
      LOG_ERROR "$identity_challenge_status_string"
      return 1
   else
      cp d_s_service_aik.pub $pca_location/s_p_service_aik.pub
   fi

   identity_challenge_status_string="Service-Token receipt from device."
   wait_loop $max_wait d_s_service_token.txt
   if [ $event_file_found == 0 ];then
     LOG_ERROR "$identity_challenge_status_string"
     return 1
   fi
   LOG_INFO "$identity_challenge_status_string"
   event_file_found=0
   test_service_token=`grep service-token \
   d_s_service_token.txt | awk '{print $2}'`
   rm -f d_s_service_token.txt

   identity_challenge_status_string="Service-Token validation."
   if [ $test_service_token == $SERVICE_TOKEN ];then
     LOG_INFO "$identity_challenge_status_string"
     return 0
   fi
   LOG_ERROR "$identity_challenge_status_string"

   return 1
}

system_software_state_validation() {

   rm -f attestation_quote.dat attestation_quote.signature
   echo "pcr-selection: $GOLDEN_PCR_SELECTION" > s_d_pcrlist.txt
   NONCE=`dd if=/dev/urandom bs=1 count=32 status=none | xxd -p -c32`
   echo "nonce: $NONCE" >> s_d_pcrlist.txt
   cp s_d_pcrlist.txt $device_location/.
   rm -f s_d_pcrlist.txt

   software_status_string="Attestation data receipt from device"
   max_wait=60
   wait_loop $max_wait attestation_quote.dat
   if [ $event_file_found == 0 ];then
      LOG_ERROR "$software_status_string"
      return 1
   fi
   LOG_INFO "$software_status_string"
   event_file_found=0

   software_status_string="Attestation signature receipt from device"
   max_wait=60
   wait_loop $max_wait attestation_quote.signature
   if [ $event_file_found == 0 ];then
      LOG_ERROR "$software_status_string"
      return 1
   fi
   LOG_INFO "$software_status_string"
   event_file_found=0

   software_status_string="Attestation quote signature validation"
   tpm2_checkquote --public d_s_service_aik.pub  --qualification "$NONCE" \
   --message attestation_quote.dat --signature attestation_quote.signature \
   --pcr pcr.bin -Q
   retval=$?
   rm -f attestation_quote.signature
   if [ $retval == 1 ];then
      LOG_ERROR "$software_status_string"
      return 1
   fi
   LOG_INFO "$software_status_string"

   software_status_string="Verification of PCR from quote against golden reference"
   testpcr=`tpm2_print -t TPMS_ATTEST attestation_quote.dat | \
   grep pcrDigest | awk '{print $2}'`
   rm -f attestation_quote.dat
   if [ "$testpcr" == "$GOLDEN_PCR" ];then
      LOG_INFO "$software_status_string"
   else
      LOG_ERROR "$software_status_string"
      echo -e "      \e[97mDevice-PCR: $testpcr\e[0m"
      echo -e "      \e[97mGolden-PCR: $GOLDEN_PCR\e[0m"
      return 1
   fi

   return 0
}

device_service_content_key_validation() {
   request_service_content_key_string="Retrieving service content key from device"
   max_wait=60
   wait_loop $max_wait d_s_service_content_key.pub
   if [ $event_file_found == 0 ];then
       LOG_ERROR "$request_service_content_key_string"
       return 1
   fi
   event_file_found=0
   LOG_INFO "$request_service_content_key_string"

   max_wait=60
   wait_loop $max_wait d_s_service_content_key_pub.sig
   if [ $event_file_found == 0 ];then
       LOG_ERROR "$request_service_content_key_string"
       return 1
   fi
   event_file_found=0
   LOG_INFO "$request_service_content_key_string"

   openssl dgst -sha256 -binary d_s_service_content_key.pub > service_content_key.pub.digest

   openssl pkeyutl \
      -verify \
      -in service_content_key.pub.digest \
      -sigfile d_s_service_content_key_pub.sig \
      -pubin \
      -inkey d_s_service_aik.pub \
      -keyform pem \
      -pkeyopt digest:sha256
   if [ $? == 1 ];then
      return 1
   fi

   return 0
}

request_device_service() {
   # Start device service registration with device identity challenge
   request_device_service_status_string="Anonymous identity validation by Privacy-CA."
   device_node_identity_challenge
   if [ $? == 1 ];then
      LOG_ERROR "$request_device_service_status_string"
      rm -f d_s_service_aik.pub
      return 1
   fi
   LOG_INFO "$request_device_service_status_string"

   # Check the device software state by getting a device quote
   request_device_service_status_string="Device system software validation."
   system_software_state_validation
   if [ $? == 1 ];then
      LOG_ERROR "$request_device_service_status_string"
      rm -f d_s_service_aik.pub
      return 1
   fi
   LOG_INFO "$request_device_service_status_string"

   # Verify service content key from the device
   request_device_service_status_string="Device service content key validation."
   device_service_content_key_validation
   if [ $? == 1 ];then
      LOG_ERROR "$request_device_service_status_string"
      rm -f d_s_service_aik.pub
      rm -f d_s_service_content_key.pub
      return 1
   fi
   LOG_INFO "$request_device_service_status_string"

   # Encrypt service data content and deliver
   echo "$SERVICE_CONTENT" > service-content.plain
    openssl rsautl -encrypt -inkey d_s_service_content_key.pub -pubin \
    -in service-content.plain -out s_d_service_content.encrypted

    cp s_d_service_content.encrypted $device_location/.
    rm -f d_s_service_aik.pub
    rm -f d_s_service_content_key.pub
    rm -f s_d_service_content.encrypted
    rm -f service-content.plain
    LOG_INFO "Sending service-content: \e[5m$SERVICE_CONTENT"

   return 0
}

tput sc
read -r -p "Demonstration purpose only, not for production. Continue? [y/N] " response
tput rc
tput el
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "===================== SERVICE-PROVIDER ====================="
else
    exit
fi

counter=1
max_wait=60
until [ $counter -gt $max_wait ]
do
   ! test -f d_s_registration.txt
   device_registration_request=$?
   ! test -f d_s_service.txt
   device_service_request=$?

   status_string="Device registration request."
   if [ $device_registration_request == 1 ];then
      device_registration
      if [ $? == 1 ];then
         LOG_ERROR "$status_string"
         exit 1
      fi
      LOG_INFO "$status_string"
      break
   elif [ $device_service_request == 1 ];then
      status_string="Device service request."
      request_device_service
      if [ $? == 1 ];then
         LOG_ERROR "$status_string"
         exit 1
      fi
      LOG_INFO "$status_string"
      break
   else
      echo -ne "Waiting $1 seconds: $counter"'\r'
   fi
   ((counter++))
   sleep 1
done

if [ $device_registration_request == 0 ];then
   if [ $device_service_request == 0 ];then
      LOG_ERROR "Exiting as there are no device requests to process"
      exit 1
   fi
fi

# No errors
exit 0
