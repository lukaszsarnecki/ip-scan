#!/usr/bin/env bash
#
# LAN IP SCANNER
# Lista zajętych i wolnych adresów IPv4 w sieci lokalnej - skan z tego
# komputera albo ze zdalnego hosta przez SSH. Wynik: tabela w terminalu.
#
# Uruchom z -h, aby zobaczyć opcje. Bez opcji pokazuje menu.

set -uo pipefail

PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

MIN_PREFIX=16          # większych sieci nie skanujemy
ASK_BELOW_PREFIX=20    # dla sieci większych niż /20 pytamy o potwierdzenie

MODE=""
SSH_TARGET=""
SSH_PORT=""
IFACE_ARG=""
ASSUME_YES=0
USE_COLOR=1
INTERACTIVE=0

TMPDIR_LOCAL=""
SSH_OPTS=()
SSH_MASTER=0
REMOTE_DIR=""
IFACE=""
CIDR=""

GREEN="" BLUE="" YELLOW="" RED="" BOLD="" NC=""


# ============================================================
# NARZĘDZIA
# ============================================================

usage() {
    cat <<EOF
Użycie: ${0##*/} [opcje]

Bez -l / -r uruchamia menu.

  -l              skan lokalny
  -r [user@]host  skan przez SSH (można podać alias z ~/.ssh/config)
  -p PORT         port SSH
  -i INTERFEJS    interfejs do skanowania (bez wybierania z listy)
  -y              nie pytaj o potwierdzenie przy dużych sieciach
  -n              bez kolorów
  -h              ta pomoc
EOF
}

setup_colors() {
    if [ "$USE_COLOR" -eq 1 ] && [ -t 1 ]; then
        GREEN=$'\e[32m' BLUE=$'\e[34m' YELLOW=$'\e[33m'
        RED=$'\e[31m' BOLD=$'\e[1m' NC=$'\e[0m'
    fi
}

info() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$NC" >&2; }
die()  { printf '%s%s%s\n' "$RED" "$*" "$NC" >&2; exit 1; }

require() {
    local cmd missing=()

    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    [ ${#missing[@]} -eq 0 ] || die "Brak programów: ${missing[*]}"
}

cleanup() {
    if [ -n "$REMOTE_DIR" ]; then
        rsh "rm -rf $REMOTE_DIR" >/dev/null 2>&1
    fi

    if [ "$SSH_MASTER" -eq 1 ]; then
        ssh "${SSH_OPTS[@]}" -O exit "$SSH_TARGET" >/dev/null 2>&1
    fi

    [ -n "$TMPDIR_LOCAL" ] && rm -rf "$TMPDIR_LOCAL"
}

# Wybór jednej pozycji z listy podanej na stdin: fzf, a bez niego
# numerowane menu. Przy jednej pozycji wybiera ją od razu.
pick() {
    local prompt="$1" header="$2" lines=() i n

    mapfile -t lines
    [ ${#lines[@]} -gt 0 ] || return 1

    if [ ${#lines[@]} -eq 1 ]; then
        printf '%s\n' "${lines[0]}"
        return 0
    fi

    if command -v fzf >/dev/null 2>&1; then
        printf '%s\n' "${lines[@]}" |
            fzf \
                --prompt="$prompt > " \
                --header="$header" \
                --height=60% \
                --border \
                --reverse
        return
    fi

    {
        echo
        echo "     $header"
        for i in "${!lines[@]}"; do
            printf '%3d) %s\n' $((i + 1)) "${lines[i]}"
        done
    } >&2

    read -rp "$prompt [1-${#lines[@]}]: " n < /dev/tty
    [[ $n =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#lines[@]} )) || return 1

    printf '%s\n' "${lines[n - 1]}"
}

copy_to_clipboard() {
    if [ -n "${WAYLAND_DISPLAY:-}" ] && command -v wl-copy >/dev/null 2>&1; then
        wl-copy
    elif [ -n "${DISPLAY:-}" ] && command -v xclip >/dev/null 2>&1; then
        xclip -selection clipboard
    else
        return 1
    fi
}


# ============================================================
# INTERFEJSY
# ============================================================

# Wysyłana też na zdalny host przez `declare -f` - musi być samowystarczalna.
list_ifaces() {
    PATH="$PATH:/usr/sbin:/sbin" ip -o -4 addr show scope global |
        awk '{
            iface = $2
            sub(/@.*/, "", iface)
            printf "%-20s %s\n", iface, $4
        }'
}

# stdin: wynik list_ifaces. Ustawia IFACE i CIDR.
choose_iface() {
    local list selected

    list=$(cat)
    [ -n "$list" ] || die "Nie znaleziono interfejsów z adresem IPv4."

    if [ -n "$IFACE_ARG" ]; then
        list=$(awk -v i="$IFACE_ARG" '$1 == i' <<< "$list")
        [ -n "$list" ] || die "Interfejs $IFACE_ARG nie ma adresu IPv4."
    fi

    selected=$(pick "Wybierz interfejs" "INTERFEJS            IPv4/CIDR" <<< "$list")
    [ -n "$selected" ] || { echo "Anulowano."; exit 0; }

    read -r IFACE CIDR <<< "$selected"
}

confirm_size() {
    local prefix="${CIDR#*/}" answer

    (( prefix >= MIN_PREFIX )) ||
        die "Sieć $CIDR jest za duża (maksymalnie /$MIN_PREFIX)."

    if (( prefix < ASK_BELOW_PREFIX && ASSUME_YES == 0 )); then
        read -rp "Sieć $CIDR to $(( (1 << (32 - prefix)) - 2 )) adresów. Kontynuować? [t/N] " answer
        [[ $answer =~ ^[tTyY]$ ]] || exit 0
    fi
}


# ============================================================
# SKANOWANIE - WSPÓLNA LOGIKA (uruchamiana jako root)
# ============================================================
#
# Funkcja jest wysyłana na zdalny host przez `declare -f`, więc nie może
# korzystać z innych funkcji ani zmiennych skryptu. Ciało w ( ) - działa
# w podpowłoce, dzięki czemu trap i exit nie wpływają na resztę skryptu.
#
# Wynik: plik z liniami IP|STATUS|MAC|PRODUCENT|HOSTNAME dla każdego adresu
# w sieci (rosnąco) oraz linią #STATS|<wykryte przez ARP>|<wykryte przez nmap>.

scan_core() (
    set -uo pipefail
    export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin" LC_ALL=C

    local iface="$1" cidr="$2" self_label="$3" result="$4"
    local ip="${cidr%/*}" prefix="${cidr#*/}"
    local ip_int=0 octet

    if ! [[ $prefix =~ ^[0-9]{1,2}$ ]] || (( 10#$prefix > 32 )) ||
       ! [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        echo "BŁĄD: nieprawidłowy adres: $cidr" >&2
        exit 2
    fi

    prefix=$((10#$prefix))

    for octet in "${BASH_REMATCH[@]:1:4}"; do
        octet=$((10#$octet))
        if (( octet > 255 )); then
            echo "BŁĄD: nieprawidłowy adres: $cidr" >&2
            exit 2
        fi
        ip_int=$(( (ip_int << 8) | octet ))
    done

    int2ip() {
        printf '%d.%d.%d.%d' \
            $(( $1 >> 24 & 255 )) $(( $1 >> 16 & 255 )) \
            $(( $1 >> 8 & 255 )) $(( $1 & 255 ))
    }

    local mask=$(( prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF ))
    local net=$(( ip_int & mask ))
    local bcast=$(( net | (~mask & 0xFFFFFFFF) ))
    local first=$net last=$bcast

    # /0-/30: pomijamy adres sieci i broadcast; w /31 i /32 każdy adres to host
    if (( prefix <= 30 )); then
        first=$(( net + 1 ))
        last=$(( bcast - 1 ))
    fi

    local network
    network="$(int2ip "$net")/$prefix"

    local tmp
    tmp=$(mktemp -d) || exit 1
    trap "rm -rf '$tmp'" EXIT

    echo "Interfejs : $iface"
    echo "Adres IP  : $ip"
    echo "Sieć      : $network ($(( last - first + 1 )) adresów)"
    echo

    # --------------------------------------------------------
    # ARP scan
    # --------------------------------------------------------

    echo "[1/3] ARP scan (arp-scan)..."

    : > "$tmp/arp.raw"

    if command -v arp-scan >/dev/null 2>&1; then
        if ! arp-scan \
                --interface="$iface" \
                --retry=3 \
                --numeric \
                "$network" \
                > "$tmp/arp.raw" \
                2> "$tmp/arp.err"; then
            echo "  UWAGA: arp-scan zakończył się błędem (wyniki tylko z nmapa):"
            tail -n 3 "$tmp/arp.err" | sed 's/^/    /'
        fi
    else
        echo "  pominięto - brak arp-scan"
    fi

    # tylko prawidłowe rekordy: IP <TAB> MAC <TAB> producent
    awk -F'\t' '
        $1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ &&
        $2 ~ /^[0-9A-Fa-f][0-9A-Fa-f](:[0-9A-Fa-f][0-9A-Fa-f])+$/
    ' "$tmp/arp.raw" > "$tmp/arp.tsv"

    # --------------------------------------------------------
    # Nmap - ping scan + odwrotny DNS (równolegle, tylko dla aktywnych)
    # --------------------------------------------------------

    echo "[2/3] Ping scan (nmap)..."

    if ! nmap -sn -e "$iface" "$network" \
            > "$tmp/nmap.raw" \
            2> "$tmp/nmap.err"; then
        echo "BŁĄD: nmap zakończył się błędem:" >&2
        tail -n 3 "$tmp/nmap.err" >&2
        exit 1
    fi

    # "Nmap scan report for nazwa (IP)" / "Nmap scan report for IP"
    # "MAC Address: AA:BB:... (Producent)"
    # -> IP <TAB> nazwa <TAB> MAC <TAB> producent
    awk '
        function flush() {
            if (addr != "") print addr "\t" name "\t" mac "\t" ven
        }
        /^Nmap scan report for / {
            flush()
            if ($NF ~ /^\(.*\)$/) {
                addr = substr($NF, 2, length($NF) - 2)
                name = $5
            } else {
                addr = $NF
                name = ""
            }
            mac = ven = ""
            next
        }
        /^MAC Address: / {
            mac = $3
            ven = $0
            sub(/^MAC Address: [^ ]+ */, "", ven)
            gsub(/^\(|\)$/, "", ven)
        }
        END { flush() }
    ' "$tmp/nmap.raw" > "$tmp/nmap.tsv"

    # --------------------------------------------------------
    # Łączenie - jeden przebieg awk zamiast procesów na każdy adres
    # --------------------------------------------------------

    echo "[3/3] Łączenie wyników..."

    local self_mac self_name
    self_mac=$(cat "/sys/class/net/$iface/address" 2>/dev/null)
    self_name=$(uname -n)

    awk -F'\t' \
        -v first="$first" \
        -v last="$last" \
        -v me="$ip" \
        -v me_mac="$self_mac" \
        -v me_name="$self_name" \
        -v me_label="$self_label" '
        function clean(s) {
            gsub(/[|\r\n]/, "/", s)
            return s == "" ? "-" : s
        }
        FILENAME == ARGV[1] {
            if (!($1 in mac)) {
                mac[$1] = $2
                ven[$1] = $3
                up[$1] = 1
                n_arp++
            }
            next
        }
        {
            if (!($1 in seen)) {
                seen[$1] = 1
                n_nmap++
            }
            up[$1] = 1
            if ($2 != "") name[$1] = $2
            if (!($1 in mac) && $3 != "") {
                mac[$1] = $3
                ven[$1] = $4
            }
        }
        END {
            for (i = first; i <= last; i++) {
                a = sprintf("%d.%d.%d.%d",
                    int(i / 16777216) % 256, int(i / 65536) % 256,
                    int(i / 256) % 256, i % 256)
                if (a == me)
                    print a "|ZAJETY|" clean(me_mac) "|" clean(me_label) "|" clean(me_name)
                else if (a in up)
                    print a "|ZAJETY|" clean(mac[a]) "|" clean(ven[a]) "|" clean(name[a])
                else
                    print a "|WOLNY|-|-|-"
            }
            print "#STATS|" (n_arp + 0) "|" (n_nmap + 0)
        }
    ' "$tmp/arp.tsv" "$tmp/nmap.tsv" > "$result" || exit 1
)


# ============================================================
# PREZENTACJA WYNIKÓW
# ============================================================

show_results() {

    local result="$1" where="$2"
    local rows="$TMPDIR_LOCAL/rows"
    local used="$TMPDIR_LOCAL/used"
    local free="$TMPDIR_LOCAL/free"
    local n_arp="" n_nmap="" n_used n_free

    grep -v '^#' "$result" > "$rows"
    IFS='|' read -r _ n_arp n_nmap < <(grep '^#STATS|' "$result")

    awk -F'|' '$2 == "ZAJETY"' "$rows" > "$used"
    awk -F'|' '$2 == "WOLNY" { print $1 }' "$rows" > "$free"

    n_used=$(wc -l < "$used")
    n_free=$(wc -l < "$free")

    echo
    printf '%s============================================================\n' "$GREEN"
    printf ' ZAJĘTE ADRESY IP\n'
    printf '============================================================%s\n\n' "$NC"

    if [ -s "$used" ]; then
        printf '%s%-16s %-18s %-32s %s%s\n' "$BOLD" IP MAC PRODUCENT HOSTNAME "$NC"
        awk -F'|' '{ printf "%-16s %-18s %-32.32s %s\n", $1, $3, $4, $5 }' "$used"
    else
        echo "Nie wykryto zajętych adresów."
    fi

    echo
    printf '%s============================================================\n' "$BLUE"
    printf ' WOLNE ADRESY IP (zakresy)\n'
    printf '============================================================%s\n\n' "$NC"

    if [ -s "$free" ]; then
        # kolejne adresy łączymy w zakresy, żeby nie wypisywać setek linii
        awk -F. '
            function flush() {
                if (cnt == 1)     print start
                else if (cnt > 1) printf "%-16s - %-16s (%d)\n", start, end, cnt
            }
            BEGIN { prev = -2 }
            {
                n = (($1 * 256 + $2) * 256 + $3) * 256 + $4
                if (n == prev + 1) {
                    end = $0
                    cnt++
                } else {
                    flush()
                    start = end = $0
                    cnt = 1
                }
                prev = n
            }
            END { flush() }
        ' "$free"
    else
        echo "Nie znaleziono wolnych adresów."
    fi

    echo
    echo "============================================================"
    echo " PODSUMOWANIE"
    echo "============================================================"
    echo
    echo "Skan   : $where, $IFACE ($CIDR)"
    echo "Zajęte : ${GREEN}${n_used}${NC}  (ARP: ${n_arp:-?}, nmap: ${n_nmap:-?})"
    echo "Wolne  : ${BLUE}${n_free}${NC}"
    echo
    echo "Uwaga: \"wolny\" = nic nie odpowiedziało w chwili skanu. Wyłączone"
    echo "urządzenia i rezerwacje DHCP nie są widoczne."

    if [ "$INTERACTIVE" -eq 1 ] && [ -s "$free" ] && command -v fzf >/dev/null 2>&1; then
        browse_free "$free"
    fi

    offer_save "$rows"
}

# FZF - przeglądanie wolnych, wybrane trafiają do schowka
browse_free() {
    local free="$1" answer selected

    echo
    read -rp "ENTER - wybierz wolne IP w fzf, q - pomiń: " answer
    [ "$answer" = q ] && return 0

    selected=$(fzf \
        --multi \
        --prompt="Wolne IP > " \
        --height=70% \
        --border \
        --reverse \
        --header="TAB = zaznacz, ENTER = wybierz, ESC = zamknij" \
        < "$free") || return 0

    echo
    echo "Wybrane:"
    echo "$selected"

    if printf '%s\n' "$selected" | copy_to_clipboard; then
        echo "(skopiowano do schowka)"
    fi
}

# Na koniec pytanie o zapis wyników do CSV (tylko gdy jest terminal).
offer_save() {
    local rows="$1" answer file default

    [ -t 0 ] || return 0

    echo
    read -rp "Zapisać wyniki do pliku CSV? [t/N] " answer
    [[ $answer =~ ^[tTyY]$ ]] || return 0

    default="lan-scan-$(date +%Y%m%d-%H%M%S).csv"
    read -rp "Nazwa pliku [$default]: " file
    file="${file:-$default}"

    if [ -e "$file" ]; then
        read -rp "Plik $file istnieje. Nadpisać? [t/N] " answer
        [[ $answer =~ ^[tTyY]$ ]] || { echo "Nie zapisano."; return 0; }
    fi

    if awk -F'|' '
        BEGIN { print "\"IP\",\"STATUS\",\"MAC\",\"VENDOR\",\"HOSTNAME\"" }
        {
            for (i = 1; i <= 5; i++) {
                gsub(/"/, "\"\"", $i)
                printf "%s\"%s\"", (i > 1 ? "," : ""), $i
            }
            print ""
        }
    ' "$rows" > "$file"; then
        echo "Zapisano: $file"
    else
        warn "Nie udało się zapisać $file"
    fi
}


# ============================================================
# SKAN LOKALNY
# ============================================================

local_scan() {

    require ip nmap sudo

    command -v arp-scan >/dev/null 2>&1 ||
        warn "Uwaga: brak arp-scan - skan tylko nmapem."

    choose_iface < <(list_ifaces)
    confirm_size

    echo
    sudo -v || die "Brak uprawnień sudo."
    echo

    sudo bash -c "$(declare -f scan_core); scan_core \"\$@\"" scan_core \
        "$IFACE" "$CIDR" "LOCAL HOST" "$TMPDIR_LOCAL/result" ||
        die "Skanowanie nie powiodło się."

    show_results "$TMPDIR_LOCAL/result" "lokalnie ($(uname -n))"
}


# ============================================================
# SKAN SSH
# ============================================================

rsh() {
    ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "$@"
}

remote_scan() {

    require ssh

    if [ -z "$SSH_TARGET" ]; then
        echo
        read -rp "Host SSH ([user@]host lub alias z ~/.ssh/config): " SSH_TARGET
        [ -n "$SSH_PORT" ] || read -rp "Port SSH [domyślny]: " SSH_PORT
    fi

    [ -n "$SSH_TARGET" ] || die "Nie podano hosta."
    [[ $SSH_TARGET != -* ]] || die "Nieprawidłowy host: $SSH_TARGET"
    [ -z "$SSH_PORT" ] || [[ $SSH_PORT =~ ^[0-9]+$ ]] || die "Nieprawidłowy port: $SSH_PORT"

    SSH_OPTS=(
        -o ControlMaster=auto
        -o ControlPersist=60
        -o "ControlPath=$TMPDIR_LOCAL/ssh-%C"
        -o ConnectTimeout=10
    )
    [ -n "$SSH_PORT" ] && SSH_OPTS+=(-p "$SSH_PORT")

    echo
    info "Łączenie z $SSH_TARGET..."
    rsh true || die "Nie udało się połączyć przez SSH."
    SSH_MASTER=1

    # --------------------------------------------------------
    # Wymagane programy na zdalnym hoście
    # --------------------------------------------------------

    local missing required

    missing=$(rsh 'PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
        for c in bash ip nmap sudo mktemp arp-scan; do
            command -v "$c" >/dev/null 2>&1 || echo "$c"
        done') || die "Nie udało się sprawdzić programów na $SSH_TARGET."

    required=$(grep -vxe arp-scan -e '' <<< "$missing" | tr '\n' ' ')
    [ -z "$required" ] || die "Brak programów na $SSH_TARGET: $required"

    if grep -qx arp-scan <<< "$missing"; then
        warn "Uwaga: brak arp-scan na $SSH_TARGET - skan tylko nmapem."
    fi

    # --------------------------------------------------------
    # Wybór interfejsu
    # --------------------------------------------------------

    info "Pobieranie interfejsów..."
    choose_iface < <(rsh "bash -c $(printf %q "$(declare -f list_ifaces); list_ifaces")")
    confirm_size

    # --------------------------------------------------------
    # Wysłanie i uruchomienie skanu
    # Katalog z mktemp (0700, losowa nazwa) - bez przewidywalnych
    # ścieżek w /tmp, które ktoś mógłby podmienić przed sudo.
    # --------------------------------------------------------

    REMOTE_DIR=$(rsh 'mktemp -d /tmp/lan-scan.XXXXXXXX') ||
        die "Nie udało się utworzyć katalogu tymczasowego na $SSH_TARGET."

    if ! [[ $REMOTE_DIR =~ ^/tmp/lan-scan\.[A-Za-z0-9]+$ ]]; then
        REMOTE_DIR=""
        die "Nieoczekiwana odpowiedź mktemp na $SSH_TARGET."
    fi

    { declare -f scan_core; echo 'scan_core "$@"'; } |
        rsh "cat > $REMOTE_DIR/scan.sh" ||
        die "Nie udało się wysłać skryptu na $SSH_TARGET."

    echo
    info "Uruchamianie zdalnego skanu (sudo może zapytać o hasło)..."
    echo

    local cmd
    printf -v cmd 'sudo bash %q %q %q %q %q' \
        "$REMOTE_DIR/scan.sh" "$IFACE" "$CIDR" "REMOTE HOST" "$REMOTE_DIR/result"

    ssh -tt "${SSH_OPTS[@]}" "$SSH_TARGET" "$cmd" ||
        die "Błąd zdalnego skanowania."

    rsh "cat $REMOTE_DIR/result" > "$TMPDIR_LOCAL/result" ||
        die "Nie udało się pobrać wyników z $SSH_TARGET."

    show_results "$TMPDIR_LOCAL/result" "$SSH_TARGET"
}


# ============================================================
# MENU
# ============================================================

menu() {

    local choice

    clear

    echo
    echo "============================================================"
    echo " LAN IP SCANNER"
    echo "============================================================"
    echo
    echo "1. Skan lokalny"
    echo "2. Skan przez SSH"
    echo "3. Wyjście"
    echo

    read -rp "Wybór [1/2/3]: " choice

    case "$choice" in
        1) MODE=local ;;
        2) MODE=remote ;;
        3|q) exit 0 ;;
        *) die "Nieprawidłowa opcja." ;;
    esac
}

main() {

    local opt

    while getopts ':lr:p:i:ynh' opt; do
        case "$opt" in
            l) MODE=local ;;
            r) MODE=remote; SSH_TARGET="$OPTARG" ;;
            p) SSH_PORT="$OPTARG" ;;
            i) IFACE_ARG="$OPTARG" ;;
            y) ASSUME_YES=1 ;;
            n) USE_COLOR=0 ;;
            h) usage; exit 0 ;;
            *) usage >&2; exit 2 ;;
        esac
    done

    setup_colors
    require awk grep sed mktemp

    TMPDIR_LOCAL=$(mktemp -d) || die "Nie udało się utworzyć katalogu tymczasowego."

    if [ -z "$MODE" ]; then
        INTERACTIVE=1
        menu
    fi

    case "$MODE" in
        local)  local_scan ;;
        remote) remote_scan ;;
    esac
}

trap cleanup EXIT
trap 'exit 130' INT TERM

main "$@"
