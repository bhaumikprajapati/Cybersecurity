import re
import pandas as pd
import matplotlib.pyplot as plt

# Regex patterns
apache_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\w+) (?P<path>[^ ]+) [^"]+" (?P<status>\d{3}) (?P<size>\d+)'
)

ssh_pattern = re.compile(
    r'(?P<month>\w+) (?P<day>\d+) (?P<time>\d+:\d+:\d+) .*sshd.* (?P<action>Failed|Accepted) .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# Generic parser function
def parse_logs(log_file, pattern):
    data = []
    with open(log_file, 'r') as file:
        for line in file:
            match = pattern.search(line)
            if match:
                data.append(match.groupdict())
    return pd.DataFrame(data)

# Brute Force Detection (SSH Logs)
ssh_df = parse_logs('ssh_test.log', ssh_pattern)
print("SSH Log Data:\n", ssh_df.head())

if not ssh_df.empty:
    failed_logins = ssh_df[ssh_df['action'] == 'Failed']
    suspicious_ips = failed_logins['ip'].value_counts()
    brute_force_ips = suspicious_ips[suspicious_ips > 5]
    print("\nSuspicious IPs with more than 5 filed SSH logins:")
    print(brute_force_ips)
else:
    print("\nNo SSH data to analyze.")

# DoS/Scanning Detection (Apache Logs)
apache_df = parse_logs('apache_test.log', apache_pattern)
print("\nApache Log Data:\n", apache_df.head())

apache_df['datetime'] = pd.to_datetime(apache_df['datetime'], format='%d/%b/%Y:%H:%M:%S %z')
apache_df.set_index('datetime', inplace=True)

requests_per_minute = (
    apache_df
    .resample('1Min')
    .apply(lambda df: df['ip'].value_counts())
    .reset_index(name='request_count')
    .rename(columns={'level_1': 'ip'})
)

suspicious_ips = requests_per_minute[requests_per_minute['request_count'] > 10]
print("\nSuspicious IPs with high request frequency (possible DoS/scanning):")
print(suspicious_ips)

# Correlation

ssh_attack_ips = set(brute_force_ips.index)
apache_attack_ips = set(suspicious_ips['ip'])

common_attackers = ssh_attack_ips.intersection(apache_attack_ips)

print("\n  IPs involved in both SSH and Apache attacks (correlated threats):")
if common_attackers:
    for ip in common_attackers:
        print(f" - {ip}")
else:
    print("No correlated IPs found.")

# Bar Chart

ip_counts = apache_df['ip'].value_counts()

# Plot
plt.figure(figsize=(10, 6))
ip_counts.plot(kind='bar', color='skyblue')
plt.title('Suspicious Apache IPs (Frequent Requests)')
plt.xlabel('IP Address')
plt.ylabel('Number of Requests')
plt.xticks(rotation=45)
plt.tight_layout()
plt.show()

# Visualize SSH brute-force IPs (only if any exist)
if not brute_force_ips.empty:
    plt.figure(figsize=(10, 6))
    brute_force_ips.plot(kind='bar', color='red')
    plt.title('SSH Brute Force Attempt Counts per IP')
    plt.xlabel('IP Address')
    plt.ylabel('Failed Attempt Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.grid(axis='y')
    plt.show()
else:
    print("\nNo brute force IPs to visualize.")

# Step 7: Export suspicious data
# Export brute force IPs
if not brute_force_ips.empty:
    brute_force_ips.to_csv('brute_force_ips.csv', header=['attempt_count'])
    print("\n Brute force IPs exported to brute_force_ips.csv")

# Export DoS-suspected IPs
if not suspicious_ips.empty:
    suspicious_ips.to_csv('dos_suspicious_ips.csv', index=False)
    print(" DoS suspected IPs exported to dos_suspicious_ips.csv")

# Export correlated IPs (if any)
if common_attackers:
    with open('correlated_ips.txt', 'w') as f:
        for ip in common_attackers:
            f.write(ip + '\n')
    print(" Correlated IPs exported to correlated_ips.txt")
