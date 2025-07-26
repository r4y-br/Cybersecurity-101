
| Option                                                              | Explanation                                                                                        |
| ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `-sL`                                                               | List scan – list targets without scanning                                                          |
| **_Host Discovery_**                                                |                                                                                                    |
| `-sn`                                                               | Ping scan – host discovery only                                                                    |
| **_Port Scanning_**                                                 |                                                                                                    |
| `-sT`                                                               | TCP connect scan – complete three-way handshake                                                    |
| `-sS`                                                               | TCP SYN – only first step of the three-way handshake                                               |
| `-sU`                                                               | UDP scan                                                                                           |
| `-Pn`                                                               | Scan hosts that appear to be down                                                                  |
| `-F`                                                                | Fast mode – scans the 100 most common ports                                                        |
| `-p[range]`                                                         | Specifies a range of port numbers – `-p-` scans all the ports                                      |
| **_Service Detection_**                                             |                                                                                                    |
| `-O`                                                                | OS detection                                                                                       |
| `-sV`                                                               | Service and version detection                                                                      |
| `-A`                                                                | OS detection, version detection, and other additions                                               |
| **_Timing_**                                                        |                                                                                                    |
| `-T<0-5>`                                                           | Timing template – paranoid (0), sneaky (1), polite (2), normal (3), aggressive (4), and insane (5) |
| `--min-parallelism <numprobes>` and `--max-parallelism <numprobes>` | Minimum and maximum number of parallel probes                                                      |
| `--min-rate <number>` and `--max-rate <number>`                     | Minimum and maximum rate (packets/second)                                                          |
| `--host-timeout`                                                    | Maximum amount of time to wait for a target host                                                   |
| **_Real-time output_**                                              |                                                                                                    |
| `-v<level>`                                                         | shows you real time scanning                                                                       |
| `-d<level>`                                                         | debugging-level output                                                                             |
| **_Report_**                                                        |                                                                                                    |
| `-oN <filename>`                                                    | save the output(normal format in a file)                                                           |
| `-oX <filename>`                                                    | save the output( XML format in a file)                                                             |
| `-oG <filename>`                                                    | save the output( `grep`-able output (useful for `grep` and `awk`)                                  |
| `-oA <basename>`                                                    | Output in all major formats                                                                        |
