/**
 * OCI ARM Instance Auto-Creation Worker
 * Cloudflare Worker version with Cron Trigger support
 */

interface Env {
  // OCI Configuration
  OCI_USER: string;
  OCI_FINGERPRINT: string;
  OCI_TENANCY: string;
  OCI_REGION: string;
  OCI_PRIVATE_KEY: string; // PEM format private key as string
  
  // Instance Configuration
  OCPUS: string;
  INSTANCE_DISPLAY_NAME: string;
  COMPARTMENT_ID: string;
  AVAILABILITY_DOMAIN: string;
  IMAGE_ID: string;
  SUBNET_ID: string;
  SSH_PUBLIC_KEY: string;
  
  // Telegram Configuration
  TELEGRAM_BOT_API: string;
  TELEGRAM_CHAT_ID: string;
  
  // Optional
  WAIT_S_FOR_RETRY?: string;
}

export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    try {
      await createOCIInstance(env);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : String(error));
    }
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    return new Response(JSON.stringify({ ok: true, mode: 'cron-only' }, null, 2), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

async function createOCIInstance(env: Env): Promise<any> {
  const ocpus = parseInt(env.OCPUS || '4');
  const memoryInGbs = ocpus * 6;
  
  // Check existing instances
  const existingInstances = await listInstances(env);
  
  let totalOcpus = 0;
  let totalMemory = 0;
  const instanceNames: string[] = [];
  
  for (const instance of existingInstances) {
    instanceNames.push(instance.displayName);
    
    if (instance.shape === 'VM.Standard.A1.Flex' && 
        !['TERMINATING', 'TERMINATED'].includes(instance.lifecycleState)) {
      totalOcpus += instance.shapeConfig?.ocpus || 0;
      totalMemory += instance.shapeConfig?.memoryInGBs || 0;
    }
  }
  
  // Pre-check resource limits
  if (totalOcpus + ocpus > 4 || totalMemory + memoryInGbs > 24) {
    throw new Error(`Resource limit exceeded: ${totalOcpus}/${4} OCPUs, ${totalMemory}/${24} GB`);
  }
  
  // Check for duplicate display name
  if (instanceNames.includes(env.INSTANCE_DISPLAY_NAME)) {
    throw new Error(`Duplicate instance name: ${env.INSTANCE_DISPLAY_NAME}`);
  }
  
  // Launch instance
  try {
    const result = await launchInstance(env, ocpus, memoryInGbs);
    const msg = `✅ 成功创建实例！\n名称: ${env.INSTANCE_DISPLAY_NAME}\n配置: ${ocpus} OCPUs / ${memoryInGbs} GB RAM\n请编辑 VNIC 以获取公网 IP。`;
    console.log(msg);
    await sendTelegramMessage(env, msg);
    return { success: true, data: result };
  } catch (error: any) {
    if (error.status === 500 || error.code === 'InternalError') {
      // Out of capacity - silent retry
      console.log('Out of host capacity, will retry on next cron trigger');
      return { success: false, reason: 'OutOfCapacity' };
    }
    throw error;
  }
}

async function listInstances(env: Env): Promise<any[]> {
  const endpoint = `https://iaas.${env.OCI_REGION}.oraclecloud.com/20160918/instances/`;
  const url = `${endpoint}?compartmentId=${encodeURIComponent(env.COMPARTMENT_ID)}`;
  
  const response = await makeOCIRequest(env, 'GET', url);
  
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Failed to list instances: ${response.status} ${errorText}`);
  }
  
  return await response.json();
}

async function launchInstance(env: Env, ocpus: number, memoryInGbs: number): Promise<any> {
  const endpoint = `https://iaas.${env.OCI_REGION}.oraclecloud.com/20160918/instances/`;
  
  const instanceDetails = {
    availabilityDomain: env.AVAILABILITY_DOMAIN,
    compartmentId: env.COMPARTMENT_ID,
    shape: 'VM.Standard.A1.Flex',
    displayName: env.INSTANCE_DISPLAY_NAME,
    sourceDetails: {
      sourceType: 'image',
      imageId: env.IMAGE_ID
    },
    createVnicDetails: {
      assignPublicIp: false,
      subnetId: env.SUBNET_ID,
      assignPrivateDnsRecord: true
    },
    metadata: {
      ssh_authorized_keys: env.SSH_PUBLIC_KEY
    },
    agentConfig: {
      isMonitoringDisabled: false,
      isManagementDisabled: false,
      pluginsConfig: [
        { name: 'Vulnerability Scanning', desiredState: 'DISABLED' },
        { name: 'Compute Instance Monitoring', desiredState: 'ENABLED' },
        { name: 'Bastion', desiredState: 'DISABLED' }
      ]
    },
    definedTags: {},
    freeformTags: {},
    instanceOptions: {
      areLegacyImdsEndpointsDisabled: false
    },
    availabilityConfig: {
      recoveryAction: 'RESTORE_INSTANCE'
    },
    shapeConfig: {
      ocpus: ocpus,
      memoryInGBs: memoryInGbs
    }
  };
  
  const response = await makeOCIRequest(env, 'POST', endpoint, instanceDetails);
  
  if (!response.ok) {
    const errorText = await response.text();
    let errorData;
    try {
      errorData = JSON.parse(errorText);
    } catch {
      errorData = { message: errorText };
    }
    
    const error: any = new Error(errorData.message || errorText);
    error.status = response.status;
    error.code = errorData.code;
    throw error;
  }
  
  return await response.json();
}

async function makeOCIRequest(
  env: Env, 
  method: string, 
  url: string, 
  body?: any
): Promise<Response> {
  const urlObj = new URL(url);
  const host = urlObj.host;
  const target = urlObj.pathname + urlObj.search;
  const date = new Date().toUTCString();
  
  // Prepare body
  const bodyString = body ? JSON.stringify(body) : '';
  const bodyBytes = new TextEncoder().encode(bodyString);
  
  // Build headers list for signing
  const headersToSign = ['date', '(request-target)', 'host'];
  
  // Build signing string components
  const signingComponents: string[] = [
    `date: ${date}`,
    `(request-target): ${method.toLowerCase()} ${target}`,
    `host: ${host}`
  ];
  
  // Add content headers for POST/PUT requests
  if (body && bodyString) {
    // Calculate SHA256 hash of body
    const bodyHash = await crypto.subtle.digest('SHA-256', bodyBytes);
    const bodyHashBase64 = btoa(String.fromCharCode(...new Uint8Array(bodyHash)));
    
    headersToSign.push('content-length', 'content-type', 'x-content-sha256');
    signingComponents.push(`content-length: ${bodyBytes.length}`);
    signingComponents.push(`content-type: application/json`);
    signingComponents.push(`x-content-sha256: ${bodyHashBase64}`);
  }
  
  const signingString = signingComponents.join('\n');
  
  // Sign the request
  const signature = await signRequest(env.OCI_PRIVATE_KEY, signingString);
  
  // Build authorization header
  const keyId = `${env.OCI_TENANCY}/${env.OCI_USER}/${env.OCI_FINGERPRINT}`;
  const headersParam = headersToSign.join(' ');
  const authHeader = `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="${headersParam}",signature="${signature}"`;
  
  const headers: Record<string, string> = {
    'date': date,
    'host': host,
    'authorization': authHeader
  };
  
  if (body && bodyString) {
    // Calculate SHA256 hash of body for x-content-sha256 header
    const bodyHash = await crypto.subtle.digest('SHA-256', bodyBytes);
    const bodyHashBase64 = btoa(String.fromCharCode(...new Uint8Array(bodyHash)));
    
    headers['content-type'] = 'application/json';
    headers['content-length'] = bodyBytes.length.toString();
    headers['x-content-sha256'] = bodyHashBase64;
  }
  
  return fetch(url, {
    method,
    headers,
    body: bodyString || undefined
  });
}

async function signRequest(privateKeyPem: string, signingString: string): Promise<string> {
  let cleanedKey = privateKeyPem.trim();

  // Check if it's already clean base64 (no headers)
  const hasHeaders = cleanedKey.includes('-----BEGIN');

  if (hasHeaders) {
    // Detect key type
    if (cleanedKey.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      throw new Error('❌ Private key is in RSA format! Must be PKCS#8 format (BEGIN PRIVATE KEY). Use: wrangler secret delete OCI_PRIVATE_KEY, then convert key and re-upload.');
    }

    if (cleanedKey.includes('ENCRYPTED')) {
      throw new Error('❌ Private key is encrypted! Must be unencrypted. Decrypt it first.');
    }

    // Remove PEM headers, footers, and all whitespace
    cleanedKey = cleanedKey
      .replace(/-----BEGIN[^-]+-----/g, '')
      .replace(/-----END[^-]+-----/g, '')
      .replace(/\r/g, '')
      .replace(/\n/g, '')
      .replace(/\s/g, '')
      .trim();
  } else {
    // Already clean, just remove whitespace
    cleanedKey = cleanedKey.replace(/\s/g, '');
  }

  // Validate base64 content
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanedKey)) {
    const invalidChars = cleanedKey.match(/[^A-Za-z0-9+/=]/g);
    const uniqueInvalid = invalidChars ? [...new Set(invalidChars)] : [];
    throw new Error(`❌ Invalid base64 characters found: ${uniqueInvalid.join(', ')}`);
  }

  let binaryDer: Uint8Array;
  try {
    binaryDer = Uint8Array.from(atob(cleanedKey), c => c.charCodeAt(0));
  } catch {
    throw new Error('Private key has invalid base64 encoding. Make sure you uploaded the complete PEM file content.');
  }

  let privateKey;
  try {
    privateKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryDer,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    );
  } catch {
    throw new Error('Private key import failed. Ensure it is PKCS#8 format (BEGIN PRIVATE KEY).');
  }

  const signatureBytes = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(signingString)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signatureBytes)));
}

async function sendTelegramMessage(env: Env, message: string): Promise<void> {
  if (!env.TELEGRAM_BOT_API || !env.TELEGRAM_CHAT_ID) {
    return;
  }
  
  try {
    const url = `https://api.telegram.org/bot${env.TELEGRAM_BOT_API}/sendMessage`;
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text: message
      })
    });
  } catch (error) {
    console.error('Failed to send Telegram message:', error);
  }
}
