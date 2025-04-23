# PayOff-Go by Chang-1205




Full PayOff protocol with zk-SNARK circuits (Enroll, CreatePayment, OfflineSpend, Revoke, Anti-Double-Spending, Daily Limit) in Go + gnark. Runs entirely in GitHub Codespaces.




## Setup & Run
1. Create a GitHub repo `payoff-go`, open in Codespaces.
2. In terminal:
   ```bash
   go mod tidy
   go build -o payoff
   ./payoff

## Chú ý
Nếu "go mod tidy" lỗi, trước đó sử dụng "go mod init..". 
Chẳng hạn: "go mod init github.com/Chang-1205/payoff-go
