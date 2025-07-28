#!/bin/bash

# The root directory of this repository
repo_dir=$(git rev-parse --show-toplevel)
# Save today's date
today=$(date +%Y%m%d)
# Load the configuration file
source $repo_dir/.env

# Create a directory to store all the zone files
# We configure them locally and then serve on remote nameservers
mkdir -p $repo_dir/data/zones/$today/{children,parent}

###############################################################################
# Step 0: store all the subdomains, configurations, and create zone files
###############################################################################

# These lists represent a particular group of subdomains
# At the end, we combine them all to a list of all subdomains

# Control subdomains (one DNSSEC-signed and other not)
subdomains_control=(
    "valid"
    "unsigned"
)

# Subdomains with various numbers of additional NSEC3 iterations
subdomains_nsec3_iter=(
    "nsec3-iter-0"
    "nsec3-iter-1"
    "nsec3-iter-50"
    "nsec3-iter-100"
    "nsec3-iter-150"
    "nsec3-iter-200"
    "nsec3-iter-500"
    "nsec3-iter-1000"
    "nsec3-iter-1500"
    "nsec3-iter-2000"
    "nsec3-iter-2500"
)

# Subdomains signed with old DNSSEC algorithms
subdomains_dnssec_old_algos=(
    "rsamd5"
    "dsa"
    "dsa-nsec3-sha1"
)

# Subdomains signed with other DNSSEC algorithms
subdomains_dnssec_algos=(
    "rsasha1"
    "rsasha1-nsec3-sha1"
    "rsasha256" 
    "rsasha512"
    "ecdsap256sha256"
    "ecdsap384sha384"
    "ed25519"
    "ed448" 
)

# Subdomains with the DS record misconfigurations
subdomains_ds=(
    "no-ds"
    "ds-bad-tag"
    "ds-bad-key-algo"
    "ds-unassigned-key-algo"
    "ds-reserved-key-algo"
    "ds-unassigned-digest-algo"
    "ds-bogus-digest-value"
)

# Subdomains with NSEC3/NSEC3PARAM records misconfigurations
subdomains_nsec3=(
    "no-nsec3"
    "no-nsec3-rrsig"
    "no-nsec3param"    
    "no-nsec3param-nsec3"
    "bad-nsec3-hash"
    "bad-nsec3-next"
    "bad-nsec3-rrsig"
    "bad-nsec3param-salt"
)

# Subdomains with DNSKEY records misconfigurations
subdomains_dnskey=(
    "no-zsk"
    "no-ksk"
    "no-dnskey"
    "bad-zsk"
    "bad-ksk"
    "no-dnskey-rrsig"
    "bad-dnskey-rrsig"
    "no-dnskey-256"
    "no-dnskey-257"
    "no-dnskey-256-257"
    "bad-zsk-algo"
    "bad-ksk-algo"
    "unassigned-zsk-algo"
    "unassigned-ksk-algo"
    "reserved-zsk-algo"
    "reserved-ksk-algo"
)

# Subdomains with RRSIG misconfigurations
subdomains_rrsig=(
    "no-rrsig-all"
    "no-rrsig-a"
    "rrsig-exp-all"
    "rrsig-exp-a"
    "rrsig-not-yet-all"
    "rrsig-not-yet-a"
    "rrsig-exp-before-all"
    "rrsig-exp-before-a"
)

# Subdomains with lame delegations, where nameservers are unreachable for various reasons
# We do not sign these domains so that we do not trigger missing key errors
subdomains_lame=(
    "allow-query-none"
    "allow-query-localhost"
    "v4-doc"
    "v6-doc"
    "not-auth"
)

# Subdomains that return different EDEs using dnsdist
subdomains_ede=(
    "ede-0"
    "ede-1"
    "ede-2"
    "ede-3"
    "ede-4"
    "ede-5"
    "ede-6"
    "ede-7"
    "ede-8"
    "ede-9"
    "ede-10"
    "ede-11"
    "ede-12"
    "ede-13"
    "ede-14"
    "ede-15"
    "ede-16"
    "ede-17"
    "ede-18"
    "ede-19"
    "ede-20"
    "ede-21"
    "ede-22"
    "ede-23"
    "ede-24"
    "ede-25"
    "ede-26"
    "ede-27"
    "ede-28"
    "ede-29"
    "ede-30"
    "ede-10000"
    "ede-50000"
)

# Subdomains that return different EDEs using dnsdist
subdomains_rcode=(
    "rcode-noerror"
    "rcode-formerr"
    "rcode-servfail"
    "rcode-nxdomain"
    "rcode-notimp"
    "rcode-refused"
    "rcode-yxdomain"
    "rcode-yxrrset"
    "rcode-nxrrset"
    "rcode-notauth"
    "rcode-notzone"
)

# All the subdomains combined
subdomains_all=(
    "${subdomains_nsec3_iter[@]}"
    "${subdomains_dnssec_old_algos[@]}"
    "${subdomains_dnssec_algos[@]}"
    "${subdomains_ds[@]}"
    "${subdomains_nsec3[@]}"
    "${subdomains_dnskey[@]}"
    "${subdomains_rrsig[@]}"
    "${subdomains_lame[@]}"
    "${subdomains_control[@]}"
    "${subdomains_ede[@]}"
    "${subdomains_rcode[@]}"
)

# Go over each subdomain in the list and create its directory and zonefile
for subdomain in "${subdomains_all[@]}"; do
    # Some of the lame subdomains do not need a zone file, 
    # because the nameservers will not be reachable in any case
    # or the answer will be injected by dnsdist
    # Convert the array to the string to make the matching below more readable
    rcode_subdomains=" ${subdomains_rcode[*]} "
    if [[ ! " v4-doc v6-doc not-auth " =~ " $subdomain " && ! $rcode_subdomains =~ " $subdomain " ]]; then
        # Compose a zone name
        zone="$subdomain.$DOMAIN"
        # Create a zone directory
        zone_dir="$repo_dir/data/zones/$today/children/$subdomain"
        mkdir -p $zone_dir

        # Create a zone file from a template
        sed \
            -e "s|{{ZONE}}|$zone|g" \
            -e "s|{{SERIAL}}|$today|g" \
            -e "s|{{NS_IP}}|$NS_CHILD_IP|g" \
            -e "s|{{A_RECORD}}|$A_RECORD|g" \
            -e "s|{{AAAA_RECORD}}|$AAAA_RECORD|g" \
            $repo_dir/configs/zonefile/example.com.db > $zone_dir/db.$zone
    fi
done

# DNSSEC algorithms have different key generation and signing options

# Algorithm name and key size in the form dnssec-keygen understands 
declare -A subdomains_dnssec_algos_configs_keygen
subdomains_dnssec_algos_configs_keygen=(
    [rsamd5]="RSAMD5 -b 1024"
    [dsa]="DSA -b 1024"
    [dsa-nsec3-sha1]="NSEC3DSA -b 1024"
    [rsasha1]="RSASHA1 -b 2048"
    [rsasha1-nsec3-sha1]="NSEC3RSASHA1 -b 2048"
    [rsasha256]="RSASHA256 -b 2048"
    [rsasha512]="RSASHA512 -b 2048"
    [ecdsap256sha256]="ECDSAP256SHA256"
    [ecdsap384sha384]="ECDSAP384SHA384"
    [ed25519]="ED25519"
    [ed448]="ED448"
)

# NSEC3 configuration if there is one
declare -A subdomains_dnssec_algos_configs_nsec3
subdomains_dnssec_algos_configs_nsec3=(
    [rsamd5]=""
    [dsa]=""
    [dsa-nsec3-sha1]="-3 - -H 0"
    [rsasha1]=""
    [rsasha1-nsec3-sha1]="-3 - -H 0"
    [rsasha256]="-3 - -H 0"
    [rsasha512]="-3 - -H 0"
    [ecdsap256sha256]="-3 - -H 0"
    [ecdsap384sha384]="-3 - -H 0"
    [ed25519]="-3 - -H 0"
    [ed448]="-3 - -H 0"
)

# This command converts RRSIG timestamps to the format "date" command understands 
ts_to_iso() {
  local ts="$1"
  echo "${ts:0:4}-${ts:4:2}-${ts:6:2}T${ts:8:2}:${ts:10:2}:${ts:12:2}Z"
}

###############################################################################
# Step 1: create zones that require an older version of dnssec-dignzone
###############################################################################

# Build and run BIND 9.12.4 that supports older DNSSEC algorithms 
# and sets the upper limit of additional iterations to 2500
docker build -t ede-bind-9.12.4 $repo_dir/configs/nameservers/bind-9.12.4
ede_bind_9_12_container=$(
    docker run \
        -v $repo_dir/data/zones/$today/children:/mnt/zones \
        -d -t ede-bind-9.12.4
    )

###############################################################################
# Step 1.1: create zones with variable additional NSEC3 iterations
###############################################################################

for subdomain in "${subdomains_nsec3_iter[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    
    # Extract the number of iterations for the current subdomain
    iter="${subdomain##*-}"

    # Sign the zone
    docker exec $ede_bind_9_12_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
        dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone -3 - -H $iter -e now+30000000 -o $zone db.$zone
        "
    # Remove DS SHA1 records not to trigger more warnings than supposed to
    sed -i '/ 8 1 /d' $repo_dir/data/zones/$today/children/$subdomain/dsset-$zone.
done

###############################################################################
# Step 1.2: create zones signed with old DNSSEC algorithms
###############################################################################

# Create and sign zones for various DNSSEC algorithms
for subdomain in "${subdomains_dnssec_old_algos[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"

    # Get configurations options for this particular algorithm
    algo_config_keygen="${subdomains_dnssec_algos_configs_keygen[$subdomain]}"
    algo_config_nsec3="${subdomains_dnssec_algos_configs_nsec3[$subdomain]}"

    # Sign the zone
    docker exec $ede_bind_9_12_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a $algo_config_keygen -n ZONE $zone && \
        dnssec-keygen -f KSK -a $algo_config_keygen -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone $algo_config_nsec3 -e now+30000000 -o $zone db.$zone
        "
done

# Kill the BIND 9.12.4 container
docker rm -f $ede_bind_9_12_container

###############################################################################
# Step 2: create all other zones with a never version of dnssec-signzone
###############################################################################

# Build and run BIND 9.18.26
docker build -t ede-bind-9.18.26 $repo_dir/configs/nameservers/bind-9.18.26
ede_bind_9_18_container=$(
    docker run \
        -v $repo_dir/data/zones/$today/children:/mnt/zones \
        -d -t ede-bind-9.18.26
    )

###############################################################################
# Step 2.1: create zones signed with other DNSSEC algorithms
###############################################################################

for subdomain in "${subdomains_dnssec_algos[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"

    # Get configurations options for this particular algorithm
    algo_config_keygen="${subdomains_dnssec_algos_configs_keygen[$subdomain]}"
    algo_config_nsec3="${subdomains_dnssec_algos_configs_nsec3[$subdomain]}"

    # Sign the zone
    docker exec $ede_bind_9_18_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a $algo_config_keygen -n ZONE $zone && \
        dnssec-keygen -f KSK -a $algo_config_keygen -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone $algo_config_nsec3 -e now+30000000 -o $zone db.$zone
        "
done

###############################################################################
# Step 2.2: create zones with DS record misconfigurations
###############################################################################

for subdomain in "${subdomains_ds[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    
    # We sign as normal
    docker exec $ede_bind_9_18_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
        dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone -3 - -H 0 -e now+30000000 -o $zone db.$zone
        "

    # And now modify the dsset-* files
    dsset_file=$repo_dir/data/zones/$today/children/$subdomain/dsset-$zone.
    sudo chown $USER:$USER $dsset_file
    case "$subdomain" in
        no-ds) # Remove the DS records
            rm $dsset_file ;;
        ds-bad-tag) # Change the key tag to 0000
            sed -i 's/\(DS \)[0-9]\{1,5\}\( 8 2\)/\100000\2/' $dsset_file ;;
        ds-bad-key-algo) # Set a different DNSKEY algorithm (8 -> 7)
            sed -i 's/\(DS [0-9]\{1,5\} \)8 2/\17 2/' $dsset_file ;;
        ds-unassigned-key-algo) # Set an unassigned DNSKEY algorithm (8 -> 100)
            sed -i 's/\(DS [0-9]\{1,5\} \)8 2/\1100 2/' $dsset_file ;;
        ds-unassigned-digest-algo) # Set an unassigned digest algorithm (2 -> 100)
            sed -i 's/\(DS [0-9]\{1,5\} \)8 2/\18 100/' $dsset_file ;;
        ds-reserved-key-algo) # Set a reserved DNSKEY algorithm (8 -> 200)
            sed -i 's/\(DS [0-9]\{1,5\} \)8 2/\1200 2/' $dsset_file ;;
        ds-bogus-digest-value) # Change the digest value
            fake_digest=$(echo -n 'I am not a real DNSKEY digest' | sha256sum | cut -d' ' -f1)
            sed -i "s/\(8 2 \).*/\1$fake_digest/" $dsset_file ;;
    esac
done

###############################################################################
# Step 2.3: create zones with NSEC3/NSEC3PARAM record misconfigurations
###############################################################################

for subdomain in "${subdomains_nsec3[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    
    # We sign as normal
    docker exec $ede_bind_9_18_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
        dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone -3 - -H 0 -e now+30000000 -o $zone db.$zone
        "
    # And now modify the signed zonefiles
    zonefile_signed=$repo_dir/data/zones/$today/children/$subdomain/db.$zone.signed
    sudo chown $USER:$USER $zonefile_signed
    case "$subdomain" in
        no-nsec3) # Remove NSEC3 records
            sed -i '/600[[:space:]]\+IN[[:space:]]\+NSEC3/,/)/d' $zonefile_signed ;;
        no-nsec3-rrsig) # Remove RRSIGs over NSEC3 records
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+RRSIG[[:space:]]\+NSEC3/,/)/d' $zonefile_signed ;;
        no-nsec3param) # Remove the NSEC3PARAM resource record
            sed -i '/0[[:space:]]\+NSEC3PARAM/d' $zonefile_signed ;;
        no-nsec3param-nsec3) # Remove both NSEC3PARAM and NSEC3
            sed -i '/0[[:space:]]\+NSEC3PARAM/d' $zonefile_signed
            sed -i '/600[[:space:]]\+IN[[:space:]]\+NSEC3/,/)/d' $zonefile_signed ;;
        bad-nsec3-hash) # The hash part of the owner name is wrong
            fake_hash=$(echo -n "I am not a real hash" | openssl dgst -sha1 -binary | base32 | \
            tr 'A-Z2-7' '0123456789ABCDEFGHIJKLMNOPQRSTUV' | head -c 32)
            sed -i -E "s/^([A-Z0-9]+)\.([a-z0-9.-]+)\.\s+[0-9]+\s+IN\s+NSEC3/${fake_hash}.\2. 60 IN NSEC3/" $zonefile_signed ;;
        bad-nsec3-next) # The next hashed owner name is wrong
            fake_hash=$(echo -n "I am not a real hash" | openssl dgst -sha1 -binary | base32 | \
            tr 'A-Z2-7' '0123456789ABCDEFGHIJKLMNOPQRSTUV' | head -c 32)
            sed -i -E "/NSEC3/ { N; s/^(\S+\s+600\s+IN\s+NSEC3.*\(\n)[ \t]*\S+/\1\t\t\t\t\t$fake_hash/ }" \
            $zonefile_signed ;;
        bad-nsec3-rrsig) # Tamper with RRSIGs over NSEC3 records
            sed -i '/RRSIG[[:space:]]\+NSEC3[[:space:]]\+8/,/)/{
            /^[[:space:]]\+[A-Za-z0-9+/]\{10,\}$/ s/[A-Za-z0-9]/X/1; b
            }' $zonefile_signed ;;
        bad-nsec3param-salt) # Set the salt length to 1
            sed -i 's/\b0[[:space:]]\+NSEC3PARAM 1 0 0 -/0	NSEC3PARAM 1 0 0 01/' $zonefile_signed
    esac
done

##############################################################################
# Step 2.4: create zones with DNSKEY record misconfigurations
##############################################################################

for subdomain in "${subdomains_dnskey[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    
    # We sign as normal
    docker exec $ede_bind_9_18_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
        dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone -3 - -H 0 -e now+30000000 -o $zone db.$zone
        "

    # And now modify the signed zonefiles
    zonefile_signed=$repo_dir/data/zones/$today/children/$subdomain/db.$zone.signed
    sudo chown $USER:$USER $zonefile_signed
    case "$subdomain" in
        no-zsk) # Remove the zone signing key (256)
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+DNSKEY[[:space:]]\+256/,/)/d' $zonefile_signed ;;
        no-ksk) # Remove the key signing key (257)
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+DNSKEY[[:space:]]\+257/,/)/d' $zonefile_signed ;;
        no-dnskey) # Remove the DNSKEY RRset
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+DNSKEY[[:space:]]\+256/,/)/d' $zonefile_signed
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+DNSKEY[[:space:]]\+257/,/)/d' $zonefile_signed ;;
        bad-zsk) # Tamper with the zone signing key (256)
            sed -i '/DNSKEY[[:space:]]\+256/,/)/{
                /^[[:space:]]\+[A-Za-z0-9+/]\{10,\}$/ s/[A-Za-z0-9]/X/1; b
                }' $zonefile_signed ;;
        bad-ksk) # Tamper with the key signing key (257)
            sed -i '/DNSKEY[[:space:]]\+257/,/)/{
                /^[[:space:]]\+[A-Za-z0-9+/]\{10,\}$/ s/[A-Za-z0-9]/X/1; b
                }' $zonefile_signed ;;
        no-dnskey-rrsig) # Remove RRSIGs over DNSKEY records
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+RRSIG[[:space:]]\+DNSKEY/,/)/d' $zonefile_signed ;;
        bad-dnskey-rrsig) # Tamper with RRSIGs over DNSKEY records
            sed -i '/RRSIG[[:space:]]\+DNSKEY[[:space:]]\+8/,/)/{
            /^[[:space:]]\+[A-Za-z0-9+/]\{10,\}$/ s/[A-Za-z0-9]/X/1; b
            }' $zonefile_signed ;;
        no-dnskey-256) # The ZSK flag is set to 0
            sed -i 's/600[[:space:]]\+DNSKEY	256 3 8 /600	DNSKEY	0 3 8 /' $zonefile_signed ;;
        no-dnskey-257) # The KSK flag is set to 0
            sed -i 's/600[[:space:]]\+DNSKEY	257 3 8 /600	DNSKEY	0 3 8 /' $zonefile_signed ;;
        no-dnskey-256-257) # Both key flags set to 0
            sed -i 's/600[[:space:]]\+DNSKEY	256 3 8 /600	DNSKEY	0 3 8 /' $zonefile_signed
            sed -i 's/600[[:space:]]\+DNSKEY	257 3 8 /600	DNSKEY	0 3 8 /' $zonefile_signed ;;
        bad-zsk-algo) # The ZSK algorithm is set to 7
            sed -i 's/600[[:space:]]\+DNSKEY	256 3 8 /600	DNSKEY	256 3 7 /' $zonefile_signed ;;
        bad-ksk-algo) # The KSK algorithm is set to 7
            sed -i 's/600[[:space:]]\+DNSKEY	257 3 8 /600	DNSKEY	257 3 7 /' $zonefile_signed ;;
        unassigned-zsk-algo) # The ZSK algorithm is set to 100
            sed -i 's/600[[:space:]]\+DNSKEY	256 3 8 /600	DNSKEY	256 3 100 /' $zonefile_signed ;;
        unassigned-ksk-algo) # The KSK algorithm is set to 100
            sed -i 's/600[[:space:]]\+DNSKEY	257 3 8 /600	DNSKEY	257 3 100 /' $zonefile_signed ;;
        reserved-zsk-algo) # The ZSK algorithm is set to 200
            sed -i 's/600[[:space:]]\+DNSKEY	256 3 8 /600	DNSKEY	256 3 200 /' $zonefile_signed ;;
        reserved-ksk-algo) # The KSK algorithm is set to 200
            sed -i 's/600[[:space:]]\+DNSKEY	257 3 8 /600	DNSKEY	257 3 200 /' $zonefile_signed ;;
    esac 
done

#############################################################################
# Step 2.5: create zones with RRSIG record misconfigurations
#############################################################################

for subdomain in "${subdomains_rrsig[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    
    # We sign as normal
    docker exec $ede_bind_9_18_container /bin/bash -c "
        cd /mnt/zones/$subdomain && \
        dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
        dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
        cat *.key >> db.$zone && \
        dnssec-signzone -3 - -H 0 -e now+30000000 -o $zone db.$zone
        "
    # Store the inception and expiration 
    # And now modify the signed zonefiles
    zonefile_signed=$repo_dir/data/zones/$today/children/$subdomain/db.$zone.signed
    sudo chown $USER:$USER $zonefile_signed
    case "$subdomain" in
        no-rrsig-all) # Remove all the signatures
            sed -i '/0[[:space:]]\+RRSIG[[:space:]]/d' $zonefile_signed ;;
        no-rrsig-a) # Remove the signature over the A RRset
            sed -i '/^[[:space:]]*[0-9]\+[[:space:]]\+RRSIG[[:space:]]\+A 8/,/)/d' $zonefile_signed ;;
        rrsig-exp-all) # All the signatures expired 1 minute after inception
            timestamps=$(grep -oE '[0-9]{14} [0-9]{14}' $zonefile_signed | head -1)
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") +1 minute" +"%Y%m%d%H%M%S")
            sed -i "s/$timestamps/$new_expiration $inception/g" $zonefile_signed ;;
        rrsig-exp-a) # The signature over the A RRset is expired
            rrsig_a_line=$(grep -nE '\bRRSIG[[:space:]]+A 8 3 600\b' $zonefile_signed | cut -d: -f1)
            ts_line=$((rrsig_a_line + 1))
            timestamps=$(sed -n "${ts_line}p" $zonefile_signed| grep -oE '[0-9]{14} [0-9]{14}')
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") +1 minute" +"%Y%m%d%H%M%S")
            sed -i "${ts_line}s|$timestamps|$new_expiration $inception|" $zonefile_signed ;;
        rrsig-not-yet-all) # All the signatures will be valid in one year
            timestamps=$(grep -oE '[0-9]{14} [0-9]{14}' $zonefile_signed | head -1)
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") +2 years" +"%Y%m%d%H%M%S")
            new_inception=$(date -u -d "$(ts_to_iso "$inception") +1 year" +"%Y%m%d%H%M%S")
            sed -i "s/$timestamps/$new_expiration $new_inception/g" $zonefile_signed ;;
        rrsig-not-yet-a) # The signature over the A RRset will be valid in one year
            rrsig_a_line=$(grep -nE '\bRRSIG[[:space:]]+A 8 3 600\b' $zonefile_signed | cut -d: -f1)
            ts_line=$((rrsig_a_line + 1))
            timestamps=$(sed -n "${ts_line}p" $zonefile_signed| grep -oE '[0-9]{14} [0-9]{14}')
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") +2 years" +"%Y%m%d%H%M%S")
            new_inception=$(date -u -d "$(ts_to_iso "$inception") +1 year" +"%Y%m%d%H%M%S")
            sed -i "${ts_line}s|$timestamps|$new_expiration $new_inception|" $zonefile_signed ;;
        rrsig-exp-before-all) # All the signatures expired before being valid
            timestamps=$(grep -oE '[0-9]{14} [0-9]{14}' $zonefile_signed | head -1)
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") -1 year" +"%Y%m%d%H%M%S")
            sed -i "s/$timestamps/$new_expiration $inception/g" $zonefile_signed ;;
        rrsig-exp-before-a) # The signature over the A RRset expired before being valid
            rrsig_a_line=$(grep -nE '\bRRSIG[[:space:]]+A 8 3 600\b' $zonefile_signed | cut -d: -f1)
            ts_line=$((rrsig_a_line + 1))
            timestamps=$(sed -n "${ts_line}p" $zonefile_signed| grep -oE '[0-9]{14} [0-9]{14}')
            expiration=${timestamps%% *}
            inception=${timestamps##* }
            new_expiration=$(date -u -d "$(ts_to_iso "$inception") -1 year" +"%Y%m%d%H%M%S")
            sed -i "${ts_line}s|$timestamps|$new_expiration $inception|" $zonefile_signed ;;
    esac
done

###############################################################################
# Step 2.6: create zones control subdomains where applicable
###############################################################################

for subdomain in "${subdomains_control[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"

    if [[ $subdomain == "valid" ]]; then
        # Sign the zone
        docker exec $ede_bind_9_18_container /bin/bash -c "
            cd /mnt/zones/$subdomain && \
            dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $zone && \
            dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $zone && \
            cat *.key >> db.$zone && \
            dnssec-signzone -3 - -H 0 -e now+30000000 -o $zone db.$zone
            "
    fi
done

# Kill the BIND 9.18.26 container
docker rm -f $ede_bind_9_18_container

###############################################################################
# Step 2.X: create the parent zone
###############################################################################

# Run the container
ede_bind_9_18_container=$(
    docker run \
        -v $repo_dir/data/zones/$today/parent:/mnt/zones \
        -d -t ede-bind-9.18.26
    )

# Create the working directory
parent_zone_dir="$repo_dir/data/zones/$today/parent/$DOMAIN"
mkdir -p $parent_zone_dir
# Create a zone file from a template
sed \
    -e "s|{{ZONE}}|$DOMAIN|g" \
    -e "s|{{SERIAL}}|$today|g" \
    -e "s|{{NS_IP}}|$NS_PARENT_IP|g" \
    -e "s|{{A_RECORD}}|$A_RECORD|g" \
    -e "s|{{AAAA_RECORD}}|$AAAA_RECORD|g" \
    $repo_dir/configs/zonefile/example.com.db > $parent_zone_dir/db.$DOMAIN

# The parent zone must include referrals to subdomains and DS records
for subdomain in "${subdomains_all[@]}"; do
    echo "$subdomain.$DOMAIN.      IN      NS     ns1.$subdomain.$DOMAIN." \
        >> $parent_zone_dir/db.$DOMAIN

    # Some domains have a different nameserver IP
    if [[ $subdomain == "v4-doc" ]]; then
        echo "ns1.$subdomain.$DOMAIN.  IN      A      198.51.100.0" \
            >> $parent_zone_dir/db.$DOMAIN
    elif [[ $subdomain == "v6-doc" ]]; then
        echo "ns1.$subdomain.$DOMAIN.  IN      AAAA      2001:db8::1" \
            >> $parent_zone_dir/db.$DOMAIN
    else
        echo "ns1.$subdomain.$DOMAIN.  IN      A      $NS_CHILD_IP" \
            >> $parent_zone_dir/db.$DOMAIN
    fi

    # Some subdomains do not have a DS record
    no_ds_subdomains=" no-ds allow-query-none allow-query-localhost v4-doc v6-doc not-auth unsigned "
    # Convert the array to the string to make the matching below more readable
    ede_subdomains=" ${subdomains_ede[*]} "
    if [[ ! $no_ds_subdomains =~ " $subdomain " && ! $ede_subdomains =~ " $subdomain " && ! $rcode_subdomains =~ " $subdomain " ]]; then
        cat $repo_dir/data/zones/$today/children/$subdomain/dsset-$subdomain.$DOMAIN. \
            >> $parent_zone_dir/db.$DOMAIN
    fi
    
    echo "" >> $parent_zone_dir/db.$DOMAIN
done

# Sign the zone
docker exec $ede_bind_9_18_container /bin/bash -c "
    cd /mnt/zones/$DOMAIN && \
    dnssec-keygen -a RSASHA256 -b 2048 -n ZONE $DOMAIN && \
    dnssec-keygen -f KSK -a RSASHA256 -b 2048 -n ZONE $DOMAIN && \
    cat *.key >> db.$DOMAIN && \
    dnssec-signzone -3 - -H 0 -e now+30000000 -o $DOMAIN db.$DOMAIN
    "

# Kill the BIND 9.18.26 container
docker rm -f $ede_bind_9_18_container

###############################################################################
# Step 3: configure the parent and child nameservers
###############################################################################

# This part of the configuration needs to be run only once
# You must have installed Docker on both nameservers already (see README.md)

if [ "$CONFIGURE_NAMESERVERS" = "true" ]; then
    # Part 1: configure BIND9 as a nameserver
    # Save the image built previously
    docker save -o $repo_dir/ede-bind-9.18.26.tar ede-bind-9.18.26:latest
    # Repeat the same thing on both parent and child
    for HOST in \
        "$NS_PARENT_USERNAME@$NS_PARENT_IP" \
        "$NS_CHILD_USERNAME@$NS_CHILD_IP"
    do
        # Send the image file
        scp -i $SSH_KEY_PRIVATE $repo_dir/ede-bind-9.18.26.tar $HOST:
        # Load the image
        # Create directories for configurations and zone files
        # Create the main named.conf file
        ssh -i $SSH_KEY_PRIVATE $HOST \
            'docker load -i ede-bind-9.18.26.tar && \
            mkdir -p bind9/{configs,zones} && \
            mkdir -p bind9/zones/zones-ede && \
            echo "include \"/etc/bind/configs/named.conf.ede\";" > bind9/configs/named.conf'
    done
    # Delete the local copy of the image
    rm $repo_dir/ede-bind-9.18.26.tar

    # Part 2: configure dnsdist as a load balancer
    docker build -t ede-dnsdist-1.9.10 $repo_dir/configs/nameservers/dnsdist-1.9.10
    # Save the image built previously
    docker save -o $repo_dir/ede-dnsdist-1.9.10.tar ede-dnsdist-1.9.10:latest
    # Send the image to the child and create a configuration directory
    scp -i $SSH_KEY_PRIVATE $repo_dir/ede-dnsdist-1.9.10.tar $NS_CHILD_USERNAME@$NS_CHILD_IP:
    # Load the image
    # Create directories for configurations and zone files
    ssh -i $SSH_KEY_PRIVATE $NS_CHILD_USERNAME@$NS_CHILD_IP \
        'docker load -i ede-dnsdist-1.9.10.tar && \
        mkdir -p dnsdist/configs'
    # Delete the local copy of the image
    rm $repo_dir/ede-dnsdist-1.9.10.tar
fi

###############################################################################
# Step 3.1: configure the child
###############################################################################

# Generate a named.conf.child file with all the zones served by the child
> $repo_dir/data/zones/$today/named.conf.child
for subdomain in "${subdomains_all[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    # Path to the config file
    named_conf=$repo_dir/data/zones/$today/named.conf.child

    # Some zones should not be served at all, as there are no zone files
    if [[ ! " v4-doc v6-doc not-auth " =~ " $subdomain " && ! $rcode_subdomains =~ " $subdomain " ]]; then
        # Fill in the named.conf file
        echo "zone \"$zone\" {" >> $named_conf
        echo "    type master;" >> $named_conf

        # There are a couple of exceptions
        if [[ $subdomain == "allow-query-none" ]]; then
            echo "    allow-query { none; };" >> $named_conf
            echo "    file \"/etc/bind/zones/zones-ede/$subdomain/db.$zone\";" >> $named_conf
        elif [[ $subdomain = "allow-query-localhost" ]]; then
            echo "    allow-query { localhost; };" >> $named_conf
            echo "    file \"/etc/bind/zones/zones-ede/$subdomain/db.$zone\";" >> $named_conf
        elif [[ $subdomain = "unsigned" || $ede_subdomains =~ " $subdomain " ]]; then
            echo "    file \"/etc/bind/zones/zones-ede/$subdomain/db.$zone\";" >> $named_conf
        else
            echo "    file \"/etc/bind/zones/zones-ede/$subdomain/db.$zone.signed\";" >> $named_conf
        fi
        echo "};" >> $named_conf
    fi
done

# Delete existing zonefiles and copy new ones
ssh -i $SSH_KEY_PRIVATE $NS_CHILD_USERNAME@$NS_CHILD_IP "rm -rf bind9/zones/zones-ede/*"
scp -i $SSH_KEY_PRIVATE $repo_dir/data/zones/$today/named.conf.child \
    $NS_CHILD_USERNAME@$NS_CHILD_IP:bind9/configs/named.conf.ede
sudo scp -i $SSH_KEY_PRIVATE -r $repo_dir/data/zones/$today/children/* \
    $NS_CHILD_USERNAME@$NS_CHILD_IP:bind9/zones/zones-ede

# Delete the existing container if any and start a new one
ssh -i $SSH_KEY_PRIVATE $NS_CHILD_USERNAME@$NS_CHILD_IP \
    'docker rm -f bind-9.18 2>/dev/null || true; \
    docker run -d --name bind-9.18 \
    -v /home/ubuntu/bind9:/etc/bind ede-bind-9.18.26 \
    named -f -c /etc/bind/configs/named.conf'

# Get the IP address of the BIND container
BIND9_IP=$(
  ssh -i $SSH_KEY_PRIVATE $NS_CHILD_USERNAME@$NS_CHILD_IP \
    "docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bind-9.18"
)

# Create the configuration file for dnsdist
dnsdist_config=$repo_dir/data/zones/$today/dnsdist.conf
> $dnsdist_config
echo "setLocal(\"0.0.0.0:53\")" >> $dnsdist_config
echo "addACL(\"0.0.0.0/0\")" >> $dnsdist_config
echo "newServer({address=\"$BIND9_IP:53\", pool=\"default\"})" >> $dnsdist_config
# For RCODE zones, extract the ecode from domain name
for subdomain in "${subdomains_rcode[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    # Extract th RCODE code
    rcode="${subdomain##*-}"
    RCODE=${rcode^^}
    echo "addAction(QNameRule(\"$zone.\"), RCodeAction(DNSRCode.$RCODE))" >> $dnsdist_config
done
# For EDE zones, extract the code from domain name
for subdomain in "${subdomains_ede[@]}"; do
    # Compose a zone name
    zone="$subdomain.$DOMAIN"
    # Extract the ede code
    ede="${subdomain##*-}"
    echo "addResponseAction(QNameRule(\"$zone.\")," \
        "SetExtendedDNSErrorResponseAction($ede, \"This EDE was intentionally inserted by dnsdist\"))" \
        >> $dnsdist_config
done
# Default rule
echo "addAction(AllRule(),PoolAction(\"default\"))" >> $dnsdist_config

# Send it to the child nameserver
scp -i $SSH_KEY_PRIVATE $dnsdist_config $NS_CHILD_USERNAME@$NS_CHILD_IP:dnsdist/configs

# Delete the existing container if any and start a new one
ssh -i $SSH_KEY_PRIVATE $NS_CHILD_USERNAME@$NS_CHILD_IP \
    'docker rm -f dnsdist-1.9.10 2>/dev/null || true; \
    docker run -d --name dnsdist-1.9.10 -p '$NS_CHILD_IP':53:53/tcp -p '$NS_CHILD_IP':53:53/udp \
    -v /home/ubuntu/dnsdist/:/etc/dnsdist ede-dnsdist-1.9.10 \
    dnsdist --supervised --config /etc/dnsdist/configs/dnsdist.conf'

##############################################################################
# Step 3.2: configure the parent
##############################################################################

# Create a named.conf.parent file for one zone only
> $repo_dir/data/zones/$today/named.conf.parent
echo "zone \"$DOMAIN\" {" >> $repo_dir/data/zones/$today/named.conf.parent
echo "    type master;" >> $repo_dir/data/zones/$today/named.conf.parent
echo "    file \"/etc/bind/zones/zones-ede/$DOMAIN/db.$DOMAIN.signed\";" \
    >> $repo_dir/data/zones/$today/named.conf.parent
echo "};" >> $repo_dir/data/zones/$today/named.conf.parent

# Delete existing zonefiles and copy new ones
ssh -i $SSH_KEY_PRIVATE $NS_PARENT_USERNAME@$NS_PARENT_IP "rm -rf bind9/zones/zones-ede/*"
scp -i $SSH_KEY_PRIVATE $repo_dir/data/zones/$today/named.conf.parent \
    $NS_PARENT_USERNAME@$NS_PARENT_IP:bind9/configs/named.conf.ede
sudo scp -i $SSH_KEY_PRIVATE -r $repo_dir/data/zones/$today/parent/$DOMAIN \
    $NS_PARENT_USERNAME@$NS_PARENT_IP:bind9/zones/zones-ede

# Delete the existing container if any and start a new one
ssh -i $SSH_KEY_PRIVATE $NS_PARENT_USERNAME@$NS_PARENT_IP \
    'docker rm -f bind-9.18 2>/dev/null || true; \
    docker run -d --name bind-9.18 -p '$NS_PARENT_IP':53:53/tcp -p '$NS_PARENT_IP':53:53/udp \
    -v /home/ubuntu/bind9:/etc/bind ede-bind-9.18.26 \
    named -f -c /etc/bind/configs/named.conf'

# Add some stuff to the parent
echo "====================================================="
echo "Please add me to Porkbun!!!!!!!!!"
cat $parent_zone_dir/dsset-$DOMAIN.
echo "ns1.$DOMAIN A $NS_PARENT_IP"
