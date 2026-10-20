# LAN IP Scanner

[Polski](#polski) | [English](#english)

---

## Polski

**LAN IP Scanner** to skrypt Bash, który sprawdza adresy IPv4 w sieci lokalnej. Może uruchomić skan na bieżącym komputerze albo na zdalnym hoście przez SSH. Wyniki pokazuje w terminalu i opcjonalnie zapisuje do pliku CSV.

### Funkcje

- Wykrywa aktywne adresy za pomocą `arp-scan` i `nmap`.
- Wyświetla adresy zajęte wraz z dostępnymi adresami MAC, producentami i nazwami hostów.
- Grupuje niewykryte adresy w zakresy.
- Pozwala skanować lokalnie lub na zdalnym hoście przez SSH.
- Opcjonalnie udostępnia wybór interfejsu i adresów z użyciem `fzf`.
- Umożliwia zapis wyników do CSV.

### Wymagania

- Linux z Bash 4 lub nowszym.
- `ip` (z pakietu iproute2), `nmap`, `sudo`, `awk`, `grep`, `sed` i `mktemp`.
- `arp-scan` jest opcjonalny, ale jego brak oznacza skanowanie wyłącznie za pomocą `nmap`.
- Dla skanowania zdalnego: klient SSH na komputerze uruchamiającym skrypt oraz Bash, `ip`, `nmap`, `sudo` i `mktemp` na zdalnym hoście. `arp-scan` na hoście zdalnym również jest opcjonalny.
- `fzf` jest opcjonalny. Bez niego wybór odbywa się w numerowanym menu.
- Do kopiowania wybranych adresów do schowka: `wl-copy` w sesji Wayland albo `xclip` w sesji X11.

### Instalacja

Sklonuj repozytorium i uruchom skrypt:

```bash
git clone https://github.com/lukaszsarnecki/ip-scan.git
cd ip-scan
bash ipscan.sh
```

Skanowanie wymaga uprawnień administratora. Przy skanowaniu lokalnym skrypt wywołuje `sudo` na komputerze, z którego został uruchomiony; przy skanowaniu zdalnym `sudo` jest uruchamiane na zdalnym hoście. W razie potrzeby skonfiguruj `sudo` tak, aby móc podać hasło w terminalu.

Przykładowa instalacja wymagań w Debianie lub Ubuntu:

```bash
sudo apt update
sudo apt install iproute2 nmap sudo arp-scan
```

Pakiet `openssh-client` jest potrzebny do skanowania przez SSH. `fzf`, `wl-clipboard` i `xclip` są opcjonalne.

### Użycie

Uruchom menu interaktywne:

```bash
bash ipscan.sh
```

Skan lokalny:

```bash
bash ipscan.sh -l
```

Skan przez SSH:

```bash
bash ipscan.sh -r user@host
bash ipscan.sh -r alias-z-ssh-config -p 2222
```

Przy skanowaniu zdalnym skrypt wybiera interfejs i podsieć skonfigurowane na zdalnym hoście. Host musi być dostępny przez SSH, a używane konto musi mieć możliwość uruchomienia `sudo`.

#### Opcje

| Opcja | Opis |
| --- | --- |
| `-l` | Skanuj lokalnie. |
| `-r [user@]host` | Skanuj przez SSH; akceptuje również alias z `~/.ssh/config`. |
| `-p PORT` | Użyj wskazanego portu SSH. |
| `-i INTERFEJS` | Wybierz interfejs bez wyświetlania listy. |
| `-y` | Pomiń pytanie o potwierdzenie dla sieci większych niż `/20`. |
| `-n` | Wyłącz kolory. |
| `-h` | Pokaż pomoc. |

Bez opcji `-l` ani `-r` uruchamia się menu. Maksymalny rozmiar skanowanej sieci to `/16`; większe sieci są odrzucane. Dla sieci większych niż `/20` skrypt prosi o potwierdzenie, chyba że podano `-y`.

### Wyniki

Tabela zajętych adresów może zawierać IP, MAC, producenta i nazwę hosta. Dane te zależą od odpowiedzi urządzeń i dostępnych narzędzi. Wolne adresy są prezentowane pojedynczo lub w połączonych zakresach. W trybie interaktywnym, gdy dostępny jest `fzf`, można wybrać wolne adresy, a następnie skopiować je do schowka, jeśli zainstalowano obsługiwane narzędzie.

Po skanowaniu uruchomionym w terminalu skrypt zapyta, czy zapisać wyniki do CSV. Plik zawiera kolumny `IP`, `STATUS`, `MAC`, `VENDOR` i `HOSTNAME`.

**Ważne:** „wolny” oznacza tylko, że adres nie odpowiedział w chwili skanowania. Wyłączone urządzenia, filtrowanie ruchu i rezerwacje DHCP mogą wpłynąć na wynik. Skanowanie nie zastępuje ewidencji adresów ani konfiguracji serwera DHCP.

### Odpowiedzialne użycie

Skanuj wyłącznie sieci i hosty, do których masz upoważnienie. Skanowanie może być widoczne dla urządzeń sieciowych lub systemów monitorujących.

### Licencja

Projekt jest udostępniany na licencji MIT. Szczegóły znajdują się w pliku [LICENSE](LICENSE).

---

## English

**LAN IP Scanner** is a Bash script that checks IPv4 addresses on a local network. It can run a scan on the current computer or on a remote host over SSH. Results are displayed in the terminal and can optionally be saved to a CSV file.

### Features

- Detects active addresses using `arp-scan` and `nmap`.
- Lists active addresses with available MAC addresses, vendors, and hostnames.
- Groups undetected addresses into ranges.
- Supports local scans and remote scans over SSH.
- Optionally provides interface and address selection with `fzf`.
- Can save results to CSV.

### Requirements

- Linux with Bash 4 or newer.
- `ip` (from iproute2), `nmap`, `sudo`, `awk`, `grep`, `sed`, and `mktemp`.
- `arp-scan` is optional; without it, scanning relies on `nmap` only.
- For remote scans: an SSH client on the computer running the script, and Bash, `ip`, `nmap`, `sudo`, and `mktemp` on the remote host. `arp-scan` on the remote host is also optional.
- `fzf` is optional. Without it, selections use a numbered menu.
- To copy selected addresses to the clipboard: `wl-copy` in a Wayland session or `xclip` in an X11 session.

### Installation

Clone the repository and run the script:

```bash
git clone https://github.com/lukaszsarnecki/ip-scan.git
cd ip-scan
bash ipscan.sh
```

Scanning requires administrator privileges. For a local scan, the script invokes `sudo` on the computer where it runs; for a remote scan, `sudo` is invoked on the remote host. If needed, configure `sudo` so you can enter your password in the terminal.

Example installation of requirements on Debian or Ubuntu:

```bash
sudo apt update
sudo apt install iproute2 nmap sudo arp-scan
```

The `openssh-client` package is required for SSH scans. `fzf`, `wl-clipboard`, and `xclip` are optional.

### Usage

Start the interactive menu:

```bash
bash ipscan.sh
```

Run a local scan:

```bash
bash ipscan.sh -l
```

Run a scan over SSH:

```bash
bash ipscan.sh -r user@host
bash ipscan.sh -r ssh-config-alias -p 2222
```

For remote scans, the script selects an interface and subnet configured on the remote host. The host must be reachable over SSH, and the account must be able to run `sudo`.

#### Options

| Option | Description |
| --- | --- |
| `-l` | Scan locally. |
| `-r [user@]host` | Scan over SSH; also accepts an alias from `~/.ssh/config`. |
| `-p PORT` | Use the specified SSH port. |
| `-i INTERFACE` | Select an interface without showing the list. |
| `-y` | Skip the confirmation prompt for networks larger than `/20`. |
| `-n` | Disable colors. |
| `-h` | Show help. |

If neither `-l` nor `-r` is supplied, the script starts the menu. The largest supported network is `/16`; larger networks are rejected. The script asks for confirmation for networks larger than `/20`, unless `-y` is supplied.

### Results

The active-address table may include IP, MAC, vendor, and hostname information. These details depend on device responses and the available tools. Free addresses are shown individually or grouped into ranges. In interactive mode, if `fzf` is available, you can select free addresses and copy them to the clipboard if a supported clipboard utility is installed.

After a scan run from a terminal, the script asks whether to save the results as CSV. The file contains the columns `IP`, `STATUS`, `MAC`, `VENDOR`, and `HOSTNAME`.

**Important:** “Free” only means that no response was detected for an address at scan time. Powered-off devices, traffic filtering, and DHCP reservations can affect the results. A scan is not a replacement for an address inventory or DHCP server configuration.

### Responsible use

Only scan networks and hosts you are authorized to assess. Scanning may be visible to network devices or monitoring systems.

### License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details.
