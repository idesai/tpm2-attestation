#!/bin/bash

# Fixed location
service_provider_location="$PWD/../SP"

# Location for node 1, node 2, etc.
device_location=""
registration_token=""

# State
event_file_found=0

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

process_device_registration_request_from_service_provider() {

    device_location=`grep device_location s_p_registration.txt | \
    awk '{print $2}'`
    registration_token=`grep registration_token s_p_registration.txt | \
    awk '{print $2}'`
    rm -f s_p_registration.txt

    return 0
}

credential_challenge() {

    file_size=`stat --printf="%s" rsa_ak.name`
    loaded_key_name=`cat rsa_ak.name | xxd -p -c $file_size`

    echo "this is my secret" > file_input.data
    tpm2_makecredential --tcti none --encryption-key rsa_ek.pub \
    --secret file_input.data --name $loaded_key_name \
    --credential-blob cred.out
    
    cp cred.out $device_location/.

    credential_status_string="Activated credential receipt from device."
    max_wait=60
    wait_loop $max_wait actcred.out
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$credential_status_string"
        return 1
    fi
    LOG_INFO "$credential_status_string"
    event_file_found=0

    diff file_input.data actcred.out
    test=$?
    rm -f rsa_ak.* file_input.data actcred.out cred.out
    credential_status_string="Credential activation challenge."
    if [ $test == 0 ];then
        LOG_INFO "$credential_status_string"
        return 0
    else
        LOG_ERROR "$credential_status_string"
        return 1
    fi
}

process_device_registration_processing_with_device() {

    touch p_d_pca_ready.txt
    cp p_d_pca_ready.txt $device_location/.
    rm -f p_d_pca_ready.txt

    process_registration_status_string="Device-ready acknowledgement receipt from device."
    max_wait=60
    wait_loop $max_wait d_p_device_ready.txt
    if [ $event_file_found == 0 ];then
        LOG_ERROR "$process_registration_status_string"
        return 1
    fi
    LOG_INFO "$process_registration_status_string"
    event_file_found=0
    rm -f d_p_device_ready.txt

    cp $device_location/rsa_ek.pub .
    cp $device_location/rsa_ak.pub .
    cp $device_location/rsa_ak.name .
    LOG_INFO "Received EKcertificate EK and AIK from device"

    credential_challenge
    if [ $? == 1 ];then
        return 1
    fi

    return 0
}

request_device_registration() {

    mkdir -p Registered_EK_Pool

    registration_request_status_string="Device info and registration-token receipt from service-provider."
    process_device_registration_request_from_service_provider
    if [ $? == 1 ];then
        LOG_ERROR "$registration_request_status_string"
        return 1
    fi
    LOG_INFO "$registration_request_status_string"

    registration_request_status_string="Registration-token dispatch to device."
    process_device_registration_processing_with_device
    if [ $? == 1 ];then
        LOG_ERROR "$registration_request_status_string"
        return 1
    else
        LOG_INFO "$registration_request_status_string"
        echo "registration_token: $registration_token" > \
        p_d_registration_token.txt
        cp p_d_registration_token.txt $device_location/.
        rm -f p_d_registration_token.txt
    fi

    mv rsa_ek.pub Registered_EK_Pool/$registration_token
    fdupes --recurse --omitfirst --noprompt --delete --quiet \
    Registered_EK_Pool | grep -q rsa_ek.pub

    return 0
}

request_device_service() {

    device_location=`grep device_location s_p_service.txt | \
    awk '{print $2}'`
    service_token=`grep service_token s_p_service.txt | \
    awk '{print $2}'`
    rm -f s_p_service.txt

    cp s_p_service_aik.pub $device_location/rsa_ak.pub
    rm -f s_p_service_aik.pub
    process_device_registration_processing_with_device
    if [ $? == 1 ];then
        LOG_ERROR "AIK received from service provider is not on the device"
        return 1
    fi

    cp rsa_ek.pub Registered_EK_Pool
    fdupes --recurse --omitfirst --noprompt --delete --quiet \
    Registered_EK_Pool | grep -q rsa_ek.pub
    retval=$?
    rm -f rsa_ek.pub Registered_EK_Pool/rsa_ek.pub
    if [ $retval == 1 ];then
        LOG_ERROR "EK from device does not belong to the registered EK pool"
        return 1
    fi

    echo "service-token: $service_token" > p_d_service_token.txt
    cp p_d_service_token.txt $device_location
    rm -f p_d_service_token.txt

    return 0
}

tput sc
read -r -p "Demonstration purpose only, not for production. Continue? [y/N] " response
tput rc
tput el
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "===================== PRIVACY-CA ====================="
else
    exit
fi


device_registration_request=0
device_service_request=0
counter=1
max_wait=60
until [ $counter -gt $max_wait ]
do
   ! test -f s_p_registration.txt
   device_registration_request=$?
   ! test -f s_p_service.txt
   device_service_request=$?

   if [ $device_registration_request == 1 ];then
      status_string="Device registration request."
      request_device_registration
      if [ $? == 1 ];then
        LOG_ERROR "$status_string"
        exit 1
      fi
      LOG_INFO "$status_string"
      break
   elif [ $device_service_request == 1 ];then
      status_string="Device service request received."
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
      LOG_ERROR "Exiting as there are no service provider requests to process."
      exit 1
   fi
fi

# No errors
exit 0