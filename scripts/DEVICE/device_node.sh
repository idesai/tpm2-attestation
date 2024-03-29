#!/bin/bash

# Fixed location
service_provider_location="$PWD/../SP"

# PCA location
privacy_ca_location=""

# Location for node 1, node 2, etc.
device_location="$PWD"

# State
event_file_found=0
device_registration_request=0
device_service_request=0

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

await_and_compelete_credential_challenge() {
    
    # Wait for credential challenge
    cred_status_string="Encrypted credential receipt from Privacy-CA."
    max_wait=60
    wait_loop $max_wait cred.out
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$cred_status_string"
        return 1
    fi
    event_file_found=0
    LOG_INFO "$cred_status_string"

    tpm2_startauthsession --policy-session --session session.ctx -Q

    TPM2_RH_ENDORSEMENT=0x4000000B
    tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT -Q

    tpm2_activatecredential --credentialedkey-context rsa_ak.ctx \
    --credentialkey-context rsa_ek.ctx --credential-blob cred.out \
    --certinfo-data actcred.out --credentialkey-auth "session:session.ctx" -Q
    
    rm -f cred.out

    tpm2_flushcontext session.ctx -Q

    rm -f session.ctx
}

device_registration() {

    # Send device location to service-provider
    echo "device_location: $device_location" > d_s_registration.txt
    cp d_s_registration.txt $service_provider_location/.
    rm -f d_s_registration.txt

    # Wait for PCA location information from service provider
    max_wait=60
    wait_loop $max_wait s_d_registration.txt
    registration_status_string="Privacy-CA information receipt from Service-Provider."
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$registration_status_string"
        return 1
    fi
    event_file_found=0
    LOG_INFO "$registration_status_string"
    privacy_ca_location=`grep privacy_ca_location s_d_registration.txt | \
    awk '{print $2}'`
    rm -f s_d_registration.txt

    registration_status_string="Acknowledgement reciept from Privacy-CA."
    wait_loop $max_wait p_d_pca_ready.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$registration_status_string"
        return 1
    fi
    event_file_found=0
    LOG_INFO "$registration_status_string"
    rm -f p_d_pca_ready.txt

    #Ready EKcertificate, EK and AIK and set ready status so PCA can pull
    tpm2_createek --ek-context rsa_ek.ctx --key-algorithm rsa \
    --public rsa_ek.pub -Q

    tpm2_createak \
        --ek-context rsa_ek.ctx \
        --ak-context rsa_ak.ctx \
        --key-algorithm rsa \
        --hash-algorithm sha256 \
        --signing-algorithm rsassa \
        --public rsa_ak.pub \
        --private rsa_ak.priv \
        --ak-name rsa_ak.name \
        -Q
    tpm2_readpublic -c rsa_ak.ctx -f pem -o rsa_ak.pub -Q

    touch fake_ek_certificate.txt

    touch d_p_device_ready.txt
    cp d_p_device_ready.txt $privacy_ca_location/.
    rm -f d_p_device_ready.txt

    registration_status_string="Credential activation challenge."
    await_and_compelete_credential_challenge
    if [ $? == 0 ];then
        LOG_INFO "$registration_status_string"
        cp actcred.out $privacy_ca_location/.
        rm -f actcred.out
        return 0
    else
        LOG_ERROR "$registration_status_string"
        return 1
    fi
}

request_device_registration () {

    device_registration
    if [ $? == 1 ];then
        return 1
    fi

    device_registration_status_string="Registration token receipt from Privacy-CA."
    max_wait=60
    wait_loop $max_wait p_d_registration_token.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$device_registration_status_string"
        return 1
    fi
    LOG_INFO "$device_registration_status_string"
    event_file_found=0
    cp p_d_registration_token.txt \
    $service_provider_location/d_s_registration_token.txt
    rm -f p_d_registration_token.txt

    return 0
}

#
# Request service with the Service-Provider
# Read the Privacy-CA location from Service-Provider
# Deliver EK, AIK, EKcertificate to the Privacy-CA
# Complete credential challenge with the Privacy-CA
# Retrieve the SERVICE-TOKEN from the Privacy-CA
# Present the SEVICE-TOKEN to the Service-Provider
#
process_device_anonymous_identity_challenge() {

   # Start device service
   test -f $device_service_aik
   if [ $? == 1 ];then
      LOG_ERROR "Aborting service request - AIK could not be found."
      return 1
   else
      echo "device_location: $device_location" > d_s_service.txt
      cp d_s_service.txt $service_provider_location/.
      rm -f d_s_service.txt
      cp $device_service_aik $service_provider_location/d_s_service_aik.pub
   fi

   identity_challenge_status_string="Privacy-CA information receipt from Service-Provider."
   max_wait=60
   wait_loop $max_wait s_d_service.txt
   if [ $event_file_found == 1 ];then
    event_file_found=0
    privacy_ca_location=`grep privacy_ca_location s_d_service.txt | \
    awk '{print $2}'`
    rm -f s_d_service.txt
    LOG_INFO "$identity_challenge_status_string"
   else
    LOG_ERROR "$identity_challenge_status_string"
    return 1
   fi

    identity_challenge_status_string="Acknowledgement receipt from Privacy-CA."
    wait_loop $max_wait p_d_pca_ready.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$identity_challenge_status_string"
        return 1
    fi

    LOG_INFO "$identity_challenge_status_string"
    event_file_found=0
    rm -f p_d_pca_ready.txt

    touch d_p_device_ready.txt
    cp d_p_device_ready.txt $privacy_ca_location/.
    rm -f d_p_device_ready.txt

    identity_challenge_status_string="Credential activation challenge."
    await_and_compelete_credential_challenge
    if [ $? == 0 ];then
        LOG_INFO "$identity_challenge_status_string"
        cp actcred.out $privacy_ca_location/.
        rm -f actcred.out
    else
        LOG_ERROR "$identity_challenge_status_string"
        rm -f actcred.out
        return 1
    fi

    identity_challenge_status_string="Service-Token receipt from Privacy-CA."
    wait_loop $max_wait p_d_service_token.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$identity_challenge_status_string"
        return 1
    fi
    LOG_INFO "$identity_challenge_status_string"
    event_file_found=0
    cp p_d_service_token.txt \
    $service_provider_location/d_s_service_token.txt
    rm -f p_d_service_token.txt

   return 0
}

process_device_software_state_validation_request() {

    software_state_string="PCR selection list receipt from Service-Provider"
    max_wait=60
    wait_loop $max_wait s_d_pcrlist.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$software_state_string"
        return 1
    fi
    LOG_INFO "$software_state_string"
    event_file_found=0
    pcr_selection=`grep pcr-selection s_d_pcrlist.txt | \
    awk '{print $2}'`
    service_provider_nonce=`grep nonce s_d_pcrlist.txt | \
    awk '{print $2}'`
    rm -f s_d_pcrlist.txt

    tpm2_quote --key-context rsa_ak.ctx --message attestation_quote.dat \
    --signature attestation_quote.signature \
    --qualification "$service_provider_nonce" \
    --pcr-list "$pcr_selection" \
    --pcr pcr.bin -Q

    cp attestation_quote.dat attestation_quote.signature pcr.bin \
    $service_provider_location/.

    return 0
}

process_encrypted_service_data_content() {

    service_data_status_string="Encrypted service-data-content receipt from Service-Provider"
    max_wait=6
    wait_loop $max_wait s_d_service_content.encrypted
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$service_data_status_string"
        return 1
    fi
    LOG_INFO "$service_data_status_string"
    event_file_found=0

    service_data_status_string="Decryption of service-data-content receipt from Service-Provider"
    tpm2 rsadecrypt -c service_content_key.ctx -o s_d_service_content.decrypted \
    s_d_service_content.encrypted -Q
    if [ $? == 1 ];then
        LOG_ERROR "$service_data_status_string"
        rm -f s_d_service_content.encrypted
        return 1
    fi
    LOG_INFO "$service_data_status_string"

    SERVICE_CONTENT=`cat s_d_service_content.decrypted`
    LOG_INFO "Service-content: \e[5m$SERVICE_CONTENT"
    rm -f s_d_service_content.*

    return 0
}

process_generate_service_content_key() {

    tpm2_create \
        -C n \
        -c service_content_key.ctx \
        -u service_content_key.pub \
        -r service_content_key.priv \
        -Q

    tpm2_readpublic \
        -c service_content_key.ctx \
        -f pem \
        -o d_s_service_content_key.pub \
        -Q
    cp d_s_service_content_key.pub $service_provider_location/.

    tpm2_sign \
        -c rsa_ak.ctx \
        -g sha256 \
        -s rsassa \
        -f plain \
        -o d_s_service_content_key_pub.sig \
        d_s_service_content_key.pub
    cp d_s_service_content_key_pub.sig $service_provider_location/.

    return 0
}

request_device_service() {

    request_service_status_string="Device anonymous identity challenge."
    process_device_anonymous_identity_challenge
    if [ $? == 1 ];then
        LOG_ERROR "$request_service_status_string"
        return 1
    fi
    LOG_INFO "$request_service_status_string"

    request_service_status_string="Device software state validation"
    process_device_software_state_validation_request
    if [ $? == 1 ];then
        LOG_ERROR "$request_service_status_string"
        return 1
    fi
    LOG_INFO "$request_service_status_string"

    request_service_status_string="Generating certified service key"
    process_generate_service_content_key
    if [ $? == 1 ];then
        LOG_ERROR "$request_service_status_string"
        return 1
    fi
    LOG_INFO "$request_service_status_string"

    request_service_status_string="Service data content processing"
    process_encrypted_service_data_content
    if [ $? == 1 ];then
        LOG_ERROR "$request_service_status_string"
        return 1
    fi

    return 0
}

tput sc
read -r -p "Demonstration purpose only, not for production. Continue? [y/N] " response
tput rc
tput el
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "===================== DEVICE-NODE ====================="
else
    exit
fi


while getopts ":hrt:" opt; do
  case ${opt} in
    h )
      echo "Pass 'r' for registration or 't' for service request"
      ;;
    r )
      device_registration_request=1
      ;;
    t )
      device_service_request=1
      device_service_aik=$OPTARG
      ;;
  esac
done
shift $(( OPTIND - 1 ))

if [ $device_registration_request == 1 ];then
   if [ $device_service_request == 1 ];then
      echo "Specify either 'registration' or 'service' request not both"
      exit 1
   fi
fi

status_string="Device registration request."
if [ $device_registration_request == 1 ];then
   request_device_registration
   if [ $? == 1 ];then
      LOG_ERROR "$status_string"
      exit 1
   fi
   LOG_INFO "$status_string"
fi

status_string="Device service request."
if [ $device_service_request == 1 ];then
   request_device_service
   if [ $? == 1 ];then
      LOG_ERROR "$status_string"
      exit 1
   fi
fi

if [ $device_registration_request == 0 ];then
   if [ $device_service_request == 0 ];then
      echo "Usage: device-node.sh [-h] [-r] [-t AIK.pub]"
      exit 1
   fi
fi

# No errors
exit 0
