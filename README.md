# deploy-key-cli

Create deploy keys using GitHub OAuth with automatically generated 4096-bit RSA key pair

Create a GitHub OAuth App and set "Authorization callback URL" to http://localhost:8080/callback (or your custom port)

```cmd
go build -o github-deploy-key .

./github-deploy-key \
  -client-id=your_client_id \
  -client-secret=your_client_secret \
  -repo=owner/repository \
  -title="Production Deploy Key"
```

Test by adding this to your CI/CD or deployment configuration:
```
ssh-add Production_Deploy_Key_deploy_key
git clone git@github.com:owner/repository.git
```