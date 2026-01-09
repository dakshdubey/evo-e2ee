# evo-e2ee

Production-grade End-to-End Encryption SDK for React and Node.js.

## Install
```bash
npm install evo-e2ee
```

## Usage
```typescript
import { evoE2EE } from "evo-e2ee"

await evoE2EE.init({
  appId: "chat-app",
  platform: "react"
})

const encrypted = await evoE2EE.encrypt("hello")
const message = await evoE2EE.decrypt(encrypted)
```

## Security

- AES-256-GCM
- Hybrid encryption
- No server-side decryption
