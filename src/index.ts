import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import FormData from 'form-data';
// install via: npm install node-fetch form-data

import fs from 'fs';
import path from 'path';

// Initialize default wallet and cluster settings
let defaultWallet: { publicKey?: string, secretKey: string | number[] } | undefined;
let defaultCluster: "devnet" | "mainnet" = "devnet";

// Helper function to parse JSON array from string if needed
function parseSecretKey(secretKeyStr: string): string | number[] {
  // Check if it looks like a JSON array
  if (secretKeyStr.startsWith('[') && secretKeyStr.endsWith(']')) {
    try {
      // Parse the JSON array
      return JSON.parse(secretKeyStr);
    } catch (err) {
      // If parsing fails, treat it as a regular string (possibly base58)
      console.error('⚠️ Failed to parse secret key as JSON array, treating as Base58 string');
      return secretKeyStr;
    }
  }
  
  // If it doesn't look like a JSON array, return as is (likely base58)
  return secretKeyStr;
}

// Parse command line arguments manually
function getCliArg(name: string): string | undefined {
  for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg.startsWith(`--${name}=`)) {
      return arg.substring(`--${name}=`.length);
    }
    if (arg === `--${name}` && i + 1 < process.argv.length) {
      return process.argv[i + 1];
    }
  }
  return undefined;
}

// Check command line arguments first
const cliWalletPublicKey = getCliArg('wallet-public-key');
const cliWalletSecretKey = getCliArg('wallet-secret-key');
const cliCluster = getCliArg('cluster');

if (cliWalletSecretKey) {
  const secretKey = parseSecretKey(cliWalletSecretKey);
  defaultWallet = {
    publicKey: cliWalletPublicKey,
    secretKey: secretKey
  };
  console.error('📝 Using wallet from command line arguments');
}

// If not from CLI, load from environment variables
if (!defaultWallet && process.env.SOLANA_WALLET_SECRET_KEY) {
  const secretKey = parseSecretKey(process.env.SOLANA_WALLET_SECRET_KEY);
  
  defaultWallet = {
    publicKey: process.env.SOLANA_WALLET_PUBLIC_KEY,
    secretKey: secretKey
  };
  console.error('📝 Using wallet from environment variables');
}

// Set default cluster from CLI or env
if (cliCluster === "mainnet" || cliCluster === "devnet") {
  defaultCluster = cliCluster;
  console.error(`🌐 Using cluster from command line: ${defaultCluster}`);
} else if (process.env.SOLANA_DEFAULT_CLUSTER === "mainnet" || process.env.SOLANA_DEFAULT_CLUSTER === "devnet") {
  defaultCluster = process.env.SOLANA_DEFAULT_CLUSTER;
  console.error(`🌐 Using cluster from environment: ${defaultCluster}`);
}

// Try loading from config file if no wallet yet
if (!defaultWallet) {
  try {
    const configPath = path.resolve('./solana-config.json');
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      
      if (config.wallet && config.wallet.secretKey) {
        defaultWallet = {
          publicKey: config.wallet.publicKey,
          secretKey: config.wallet.secretKey
        };
        console.error('📝 Using wallet from solana-config.json');
      }
      
      // Only set cluster if not already set from CLI or env
      if (!cliCluster && !process.env.SOLANA_DEFAULT_CLUSTER) {
        if (config.defaultCluster === "mainnet" || config.defaultCluster === "devnet") {
          defaultCluster = config.defaultCluster;
          console.error(`🌐 Using cluster from config file: ${defaultCluster}`);
        }
      }
    }
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    console.error(`⚠️ Error loading config file: ${errorMessage}`);
  }
}

// Log wallet info if available
if (defaultWallet) {
  const secretKeyType = Array.isArray(defaultWallet.secretKey) 
    ? 'array of numbers' 
    : 'Base58 encoded string';
  
  console.error(`💳 Default wallet loaded with public key: ${defaultWallet.publicKey || '(not provided)'}`);
  console.error(`💳 Secret key format: ${secretKeyType}`);
}

const API_BASE_URL = "https://octomcp.xyz";
const SOLANA_BUILD_ENDPOINT = `${API_BASE_URL}/build`;
const SOLANA_DEPLOY_ENDPOINT = `${API_BASE_URL}/deploy`;

const server = new McpServer({
  name: "solana-builder",
  version: "1.0.0",
});

// Define types for the API responses
interface BuildErrorOld {
  error: string;
  syntaxErrors?: string[];
  compilationErrors?: Array<{
    message: string;
    location?: string;
  }>;
  fullError?: string;
  buildId?: string;
  containerUsed?: string;
}

interface BuildErrorNew {
  error: string;
  buildError?: string;  // Raw error output
  rawOutput?: {
    stdout: string;
    stderr: string;
  };
  availableFiles?: string[];
  buildOutput?: string;
}

type BuildError = BuildErrorOld | BuildErrorNew;

interface BuildSuccess {
  message: string;
  buildId: string;
  programId: string;
  moduleName: string;
  containerUsed: string;
  idl: {
    address: string;
    metadata?: {
      name: string;
      version: string;
      spec?: string;
      description?: string;
    };
    instructions?: Array<{
      name: string;
      args?: any[];
    }>;
    accounts?: any[];
    types?: any[];
  };
  soPath: string;
}

type BuildResponse = BuildSuccess | BuildError;

// Interface for the deploy response
interface DeploySuccess {
  message: string;
  programId: string;
  raw?: string;
  containerUsed?: string;
  usedSize?: number;
  calculatedSize?: number;
  programSizeBytes?: number;
}

interface DeployError {
  error: string;
  details?: any;
}

type DeployResponse = DeploySuccess | DeployError;

/**
 * Enhanced function to validate if Solana code is complete and ready for build
 * This function performs more thorough checks to ensure code completeness
 */
function isCodeComplete(code: string): { complete: boolean; reason?: string } {
  // Check for essential Solana program components
  const hasDeclareMacro = code.includes('declare_id!');
  if (!hasDeclareMacro) {
    return { 
      complete: false, 
      reason: "Missing declare_id! macro which is required for a Solana program" 
    };
  }

  const hasProgramModule = code.includes('#[program]') && code.includes('mod ');
  if (!hasProgramModule) {
    return { 
      complete: false, 
      reason: "Missing #[program] module declaration which is required for a Solana program" 
    };
  }

  // Check for balanced braces
  const openBraces = (code.match(/{/g) || []).length;
  const closeBraces = (code.match(/}/g) || []).length;
  if (openBraces !== closeBraces) {
    return { 
      complete: false, 
      reason: `Unbalanced braces: ${openBraces} opening braces and ${closeBraces} closing braces` 
    };
  }

  // Check for balanced parentheses
  const openParens = (code.match(/\(/g) || []).length;
  const closeParens = (code.match(/\)/g) || []).length;
  if (openParens !== closeParens) {
    return { 
      complete: false, 
      reason: `Unbalanced parentheses: ${openParens} opening and ${closeParens} closing` 
    };
  }

  // Check for balanced square brackets
  const openBrackets = (code.match(/\[/g) || []).length;
  const closeBrackets = (code.match(/\]/g) || []).length;
  if (openBrackets !== closeBrackets) {
    return { 
      complete: false, 
      reason: `Unbalanced square brackets: ${openBrackets} opening and ${closeBrackets} closing` 
    };
  }

  // Check if code doesn't end abruptly
  const abruptEndingPatterns = [',', '{', '(', '[', '...', ';'];
  for (const pattern of abruptEndingPatterns) {
    if (code.trim().endsWith(pattern)) {
      return { 
        complete: false, 
        reason: `Code ends abruptly with '${pattern}', suggesting it's incomplete` 
      };
    }
  }

  // Check for bare minimum expected elements in a Solana program
  if (!code.includes('use solana_program')) {
    return { 
      complete: false, 
      reason: "Missing 'use solana_program' import which is typically required" 
    };
  }

  // Check for common missing structures like pubkey
  const hasPubkey = code.includes('Pubkey') || code.includes('pubkey');
  const hasEntrypoint = code.includes('entrypoint!');
  
  if (!hasPubkey && !hasEntrypoint) {
    return { 
      complete: false, 
      reason: "Missing important Solana components (Pubkey or entrypoint)" 
    };
  }

  // Check for instructional placeholders that suggest incomplete code
  if (code.includes('// TODO') || code.includes('/* TODO') || 
      code.includes('// FIXME') || code.includes('/* FIXME')) {
    return { 
      complete: false, 
      reason: "Contains TODO or FIXME comments, suggesting work in progress" 
    };
  }

  // Check for comments asking for help or indicating an issue
  if (code.toLowerCase().includes('help') && 
      (code.includes('//') || code.includes('/*'))) {
    return { 
      complete: false, 
      reason: "Contains comments asking for help, suggesting code is not finalized" 
    };
  }

  // Check code length - extremely short code is likely incomplete
  if (code.length < 100) {
    return { 
      complete: false, 
      reason: "Code is too short to be a complete Solana program" 
    };
  }

  return { complete: true };
}

// Helper to generate links to block explorers
function generateExplorerLinks(programId: string, cluster: string = "devnet"): string {
  const clusterSuffix = cluster === "mainnet" ? "" : `?cluster=${cluster}`;
  
  return `🔍 View your program on block explorers:
• Solana Explorer: https://${cluster === "mainnet" ? "" : `${cluster}.`}explorer.solana.com/address/${programId}
• Solscan: https://solscan.io/account/${programId}${clusterSuffix}`;
}

// MCP Tool: Validate Solana Program
server.tool(
  "validate-solana-program",
  "Validate a Solana program before building",
  {
    code: z.string().min(1).describe("lib.rs code content to validate"),
  },
  async ({ code }) => {
    try {
      // Perform thorough code validation
      const validationResult = isCodeComplete(code);
      
      if (!validationResult.complete) {
        return {
          content: [
            {
              type: "text",
              text: `⚠️ The code appears to be incomplete or invalid.\n\nIssue: ${validationResult.reason}\n\nPlease review and fix the issue before building.`,
            },
          ],
        };
      }
      
      return {
        content: [
          {
            type: "text",
            text: `✅ Code validation successful! The Solana program code appears to be complete and ready for building.\n\nYou can now proceed with the build-solana-program tool.`,
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: `❌ Error during code validation: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
);

// MCP Tool: Build Solana Program - Enhanced with additional validation
server.tool(
  "build-solana-program",
  "Build a Solana program from lib.rs file",
  {
    code: z.string().min(1).describe("lib.rs code content to build"),
    forceBuild: z.boolean().default(false).describe("Force build even if validation fails (use with caution)"),
  },
  async ({ code, forceBuild }) => {
    try {
      // Enhanced validation before building
      const validationResult = isCodeComplete(code);
      
      // If code is incomplete and forceBuild is not enabled, return validation error
      if (!validationResult.complete && !forceBuild) {
        return {
          content: [
            {
              type: "text",
              text: `⚠️ The code appears to be incomplete or invalid. Build aborted.\n\nIssue: ${validationResult.reason}\n\nPlease use the validate-solana-program tool first to ensure your code is complete before building. If you're certain your code is ready despite this warning, you can use forceBuild=true parameter.`,
            },
          ],
        };
      }
      
      // Log message if force building with incomplete code
      if (!validationResult.complete && forceBuild) {
        console.error(`⚠️ Warning: Force building with incomplete code. Issue: ${validationResult.reason}`);
      }
      
      const formData = new FormData();
      
      // Create a Buffer from the code string
      const fileBuffer = Buffer.from(code, 'utf-8');
      
      // Append the file to formData
      formData.append('lib', fileBuffer, {
        filename: 'lib.rs',
        contentType: 'text/plain'
      });

      // Log that we're sending the build request
      console.error(`🔨 Sending build request to ${SOLANA_BUILD_ENDPOINT}...`);

      const res = await fetch(SOLANA_BUILD_ENDPOINT, {
        method: "POST",
        body: formData,
      });

      const responseData = await res.json() as BuildResponse;

      if (!res.ok) {
        const errorRes = responseData as BuildError;
        
        // Handle old format (with compilationErrors or fullError)
        if ('compilationErrors' in errorRes || 'fullError' in errorRes) {
          // Extract the actual compilation errors from fullError or stderr
          let errorText = '';
          
          if (errorRes.fullError) {
            // Parse the fullError to get just the actual error messages
            const lines = errorRes.fullError.split('\n');
            const errorStart = lines.findIndex(line => line.includes('error['));
            if (errorStart !== -1) {
              errorText = lines.slice(errorStart).join('\n');
            } else {
              errorText = errorRes.fullError;
            }
          }
          
          return {
            content: [
              {
                type: "text",
                text: `❌ Build failed with compilation errors:\n\n${errorText}\n\nPlease fix these errors and try again.`,
              },
            ],
          };
        }
        // Handle new format (with buildError)
        else {
          let errorText = '';
          
          if ('buildError' in errorRes && errorRes.buildError) {
            errorText = errorRes.buildError;
          } else if ('buildOutput' in errorRes && errorRes.buildOutput) {
            errorText = errorRes.buildOutput;
          } else {
            errorText = errorRes.error;
          }
          
          return {
            content: [
              {
                type: "text",
                text: `❌ Build failed:\n\n${errorText}\n\nPlease fix these errors and try again.`,
              },
            ],
          };
        }
      }

      const successRes = responseData as BuildSuccess;
      
      // Format the successful response
      let resultText = `✅ Solana program built successfully!\n\n`;
      resultText += `Build ID: ${successRes.buildId}\n`;
      resultText += `Program ID: ${successRes.programId}\n`;
      resultText += `Module Name: ${successRes.moduleName}\n`;
      resultText += `Container Used: ${successRes.containerUsed}\n\n`;
      
      resultText += `📦 IDL Information:\n`;
      resultText += `- Program Address: ${successRes.idl.address}\n`;
      resultText += `- Instructions: ${successRes.idl.instructions?.length || 0}\n`;
      resultText += `- Accounts: ${successRes.idl.accounts?.length || 0}\n`;
      resultText += `- Types: ${successRes.idl.types?.length || 0}\n\n`;
      
      if (successRes.idl.instructions && successRes.idl.instructions.length > 0) {
        resultText += `Available Instructions:\n`;
        successRes.idl.instructions.forEach((instruction, index) => {
          resultText += `${index + 1}. ${instruction.name}: ${instruction.args?.length || 0} args\n`;
        });
      }
      
      resultText += `\n🔗 Program SO file: ${successRes.soPath}`;
      resultText += `\n\n✅ Build completed successfully! To deploy this program, please provide your wallet keypair.`;
      resultText += `\n\nTo deploy, use the deploy-solana-program tool with:`;
      resultText += `\n- Build ID: ${successRes.buildId}`;
      resultText += `\n- Cluster: "devnet" or "mainnet"`;
      resultText += `\n- Wallet: Your Solana wallet keypair (will be auto-generated if not provided)`;
      resultText += `\n\nIf you have a wallet keypair, please provide it in the following format:`;
      resultText += `\n{`;
      resultText += `\n  "publicKey": "optional-public-key-string",`;
      resultText += `\n  "secretKey": [array-of-numbers] or "base58-encoded-string"`;
      resultText += `\n}`;

      return {
        content: [
          {
            type: "text",
            text: resultText,
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: `❌ Failed to build Solana program: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
);

//  AI Audit Tool Implementation

// Advanced code analysis utilities
interface CodeContext {
  functions: Array<{
    name: string;
    body: string;
    startLine: number;
    endLine: number;
  }>;
  structs: Array<{
    name: string;
    attributes: string[];
    body: string;
  }>;
  imports: string[];
  constraints: string[];
}

// Parse code structure for better analysis
function parseCodeStructure(code: string): CodeContext {
  const lines = code.split('\n');
  const context: CodeContext = {
    functions: [],
    structs: [],
    imports: [],
    constraints: []
  };

  // Extract imports
  const importMatches = code.match(/use\s+[^;]+;/g) || [];
  context.imports = importMatches.map(imp => imp.trim());

  // Extract functions with their bodies
  const functionRegex = /(?:pub\s+)?fn\s+(\w+)[^{]*\{/g;
  let match;
  while ((match = functionRegex.exec(code)) !== null) {
    const functionName = match[1];
    const startIndex = match.index;
    const startLine = code.substring(0, startIndex).split('\n').length;
    
    // Find matching closing brace
    let braceCount = 0;
    let endIndex = startIndex;
    for (let i = startIndex; i < code.length; i++) {
      if (code[i] === '{') braceCount++;
      if (code[i] === '}') braceCount--;
      if (braceCount === 0) {
        endIndex = i;
        break;
      }
    }
    
    const functionBody = code.substring(startIndex, endIndex + 1);
    const endLine = code.substring(0, endIndex).split('\n').length;
    
    context.functions.push({
      name: functionName,
      body: functionBody,
      startLine,
      endLine
    });
  }

  // Extract struct definitions with better parsing
  const structRegex = /((?:#\[[^\]]+\]\s*)*)\bstruct\s+(\w+)[^{]*\{([^}]+)\}/gs;
  while ((match = structRegex.exec(code)) !== null) {
    const attributes = match[1] ? match[1].match(/#\[[^\]]+\]/g) || [] : [];
    const structName = match[2];
    const structBody = match[3];
    
    context.structs.push({
      name: structName,
      attributes: attributes.map(attr => attr.trim()),
      body: structBody
    });
  }

  // Extract constraints (has_one, constraint = patterns)
  const constraintMatches = code.match(/(?:has_one|constraint)\s*=\s*[^,\]]+/g) || [];
  context.constraints = constraintMatches.map(c => c.trim());

  return context;
}

// Security patterns and anti-patterns for Solana programs
interface SecurityCheck {
  name: string;
  analyzer: (code: string, context: CodeContext) => SecurityIssue[];
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  recommendation: string;
  category: 'access_control' | 'arithmetic' | 'account_validation' | 'data_handling' | 'best_practices' | 'resource_management';
}

interface SecurityIssue {
  line?: number;
  context?: string;
  details?: string;
}

const SECURITY_CHECKS: SecurityCheck[] = [
  // Critical Security Issues
  {
    name: "Missing Owner Check",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      
      // Look for functions that modify state without proper authority checks
      context.functions.forEach(func => {
        const hasStateModification = /&mut|\.try_borrow_mut|\.borrow_mut/.test(func.body);
        
        if (hasStateModification) {
          // Check for various forms of authority validation
          const hasRequireCheck = /require!\s*\([^)]*(?:authority|owner|signer)[^)]*\.key\(\)|require!\s*\([^)]*==/.test(func.body);
          const hasConstraintValidation = /has_one\s*=\s*(?:authority|owner)|constraint\s*=.*(?:authority|owner)/.test(code);
          const hasSignerCheck = /require!\s*\([^)]*\.is_signer/.test(func.body);
          
          // Check if this is actually a privileged operation that needs owner checks
          const isPrivileged = /transfer|close|initialize|update|admin|withdraw|mint|break/.test(func.name);
          const isPublicFunction = /pub\s+fn/.test(func.body);
          
          if (isPrivileged && isPublicFunction && !hasRequireCheck && !hasConstraintValidation && !hasSignerCheck) {
            issues.push({
              line: func.startLine,
              context: `Function: ${func.name}`,
              details: "Privileged state-modifying function without explicit authority validation"
            });
          }
        }
      });
      
      return issues;
    },
    severity: 'critical',
    description: "Functions modifying state without proper authority validation",
    recommendation: "Add require!() checks, has_one constraints, or other authority validation before state modifications.",
    category: 'access_control'
  },
  
  {
    name: "Unchecked Arithmetic Operations",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      
      context.functions.forEach(func => {
        // Look for arithmetic operations that could overflow
        const arithmeticRegex = /(\w+)\s*([+\-*\/])\s*(\w+)/g;
        let match;
        
        while ((match = arithmeticRegex.exec(func.body)) !== null) {
          const operation = match[0];
          const operator = match[2];
          
          // Skip if it's already using checked arithmetic
          if (/checked_(?:add|sub|mul|div)|saturating_(?:add|sub|mul)/.test(func.body.substring(Math.max(0, match.index - 50), match.index + 50))) {
            continue;
          }
          
          // Skip simple constant arithmetic or assignments
          if (/^\d+$/.test(match[1]) && /^\d+$/.test(match[3])) {
            continue;
          }
          
          // Skip if it's part of an assignment without risk
          if (/=\s*$/.test(func.body.substring(Math.max(0, match.index - 10), match.index))) {
            continue;
          }
          
          // This is potentially risky arithmetic
          const line = func.body.substring(0, match.index).split('\n').length + func.startLine - 1;
          issues.push({
            line,
            context: `Operation: ${operation}`,
            details: `Arithmetic operation '${operator}' without overflow protection`
          });
        }
      });
      
      return issues;
    },
    severity: 'high',
    description: "Arithmetic operations without overflow/underflow protection",
    recommendation: "Use checked_add(), checked_sub(), checked_mul(), or checked_div() for arithmetic operations to prevent overflow/underflow attacks.",
    category: 'arithmetic'
  },

  {
    name: "Missing Signer Validation",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      const processedAccounts = new Set<string>(); // Prevent duplicates
      
      // Extract all instruction contexts (structs with accounts)
      const instructionContexts = context.structs.filter(struct => 
        struct.attributes.some(attr => attr.includes('derive') && attr.includes('Accounts'))
      );
      
      instructionContexts.forEach(instructionCtx => {
        const signerMatches = instructionCtx.body.match(/(\w+):\s*Signer<'info>/g) || [];
        
        signerMatches.forEach(signerDecl => {
          const accountName = signerDecl.split(':')[0].trim();
          
          // Skip if already processed (prevent duplicates)
          if (processedAccounts.has(accountName)) {
            return;
          }
          processedAccounts.add(accountName);
          
          // Anchor's Signer<'info> automatically validates signatures, so this is usually fine
          // Only flag if this is a privileged signer that needs additional validation
          const isPrivilegedSigner = accountName.includes('authority') || accountName.includes('admin') || accountName.includes('owner');
          
          if (isPrivilegedSigner) {
            // Check for additional validation patterns
            const hasExplicitValidation = new RegExp(
              `(?:require!|constraint).*${accountName}\\.|has_one\\s*=\\s*${accountName}|${accountName}\\s*@`, 'i'
            ).test(code);
            
            // Check if there's a has_one constraint relating to this signer
            const hasOwnershipConstraint = new RegExp(`has_one\\s*=\\s*${accountName}`, 'i').test(code);
            
            // Only flag if it's a privileged signer without ownership constraints
            if (!hasExplicitValidation && !hasOwnershipConstraint) {
              issues.push({
                context: `Instruction: ${instructionCtx.name}, Account: ${accountName}`,
                details: "Privileged signer account without explicit ownership validation beyond signature check"
              });
            }
          }
        });
      });
      
      return issues;
    },
    severity: 'medium', // Reduced from 'high' since Signer<'info> provides basic protection
    description: "Privileged signer accounts that may benefit from additional validation",
    recommendation: "For privileged operations, consider adding 'has_one = owner' constraints or explicit authority checks beyond signature validation.",
    category: 'access_control'
  },

  {
    name: "Missing Rent Exemption Check",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      
      context.functions.forEach(func => {
        // Look for account creation patterns
        const hasAccountCreation = /create_account|allocate|assign|space\s*=/.test(func.body);
        
        if (hasAccountCreation) {
          // Check if rent exemption is verified
          const hasRentCheck = /rent.*minimum_balance|\.is_exempt|rent_exempt/.test(func.body);
          
          if (!hasRentCheck) {
            issues.push({
              line: func.startLine,
              context: `Function: ${func.name}`,
              details: "Account creation without rent exemption validation"
            });
          }
        }
      });
      
      return issues;
    },
    severity: 'high',
    description: "Account creation without rent exemption validation",
    recommendation: "Ensure accounts have sufficient lamports for rent exemption using Rent::minimum_balance() checks.",
    category: 'account_validation'
  },

  // Medium Priority Issues
  {
    name: "Missing Error Handling",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      
      context.functions.forEach(func => {
        const unwrapMatches = func.body.match(/\.unwrap\(\)|\.expect\(/g);
        
        if (unwrapMatches) {
          // Check if there's proper error handling context
          const hasErrorHandling = /Result<|Error|try_|match\s+.*\{/.test(func.body);
          
          if (!hasErrorHandling) {
            issues.push({
              line: func.startLine,
              context: `Function: ${func.name}`,
              details: `Found ${unwrapMatches.length} unwrap/expect calls without error handling`
            });
          }
        }
      });
      
      return issues;
    },
    severity: 'medium',
    description: "Use of unwrap() or expect() without proper error handling",
    recommendation: "Replace unwrap() and expect() with proper error handling using ? operator or match statements.",
    category: 'best_practices'
  },

  // Low Priority Issues
  {
    name: "TODO/FIXME Comments",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      const todoMatches = code.match(/(?:TODO|FIXME|XXX|HACK):[^\n]*/gi);
      
      if (todoMatches) {
        todoMatches.forEach(todo => {
          const index = code.indexOf(todo);
          const line = code.substring(0, index).split('\n').length;
          issues.push({
            line,
            context: todo.trim(),
            details: "Unresolved development comment"
          });
        });
      }
      
      return issues;
    },
    severity: 'low',
    description: "Unresolved TODO/FIXME comments found",
    recommendation: "Resolve all TODO and FIXME comments before deploying to production.",
    category: 'best_practices'
  },

  {
    name: "Debug Print Statements",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      const debugMatches = code.match(/(?:println!|dbg!|print!)\s*\([^)]*\)/g);
      
      if (debugMatches) {
        debugMatches.forEach(debug => {
          const index = code.indexOf(debug);
          const line = code.substring(0, index).split('\n').length;
          issues.push({
            line,
            context: debug.trim(),
            details: "Debug statement should be removed for production"
          });
        });
      }
      
      return issues;
    },
    severity: 'low',
    description: "Debug print statements found",
    recommendation: "Remove debug print statements from production code to reduce compute costs.",
    category: 'best_practices'
  },

  // Info Level
  {
    name: "Gas Optimization Opportunity",
    analyzer: (code: string, context: CodeContext) => {
      const issues: SecurityIssue[] = [];
      
      // Look for dynamic data structures in account definitions
      context.structs.forEach(struct => {
        if (struct.attributes.some(attr => attr.includes('#[account]'))) {
          const hasDynamicTypes = /Vec<|String|HashMap|BTreeMap/.test(struct.body);
          if (hasDynamicTypes) {
            issues.push({
              context: `Struct: ${struct.name}`,
              details: "Account struct uses dynamic data structures"
            });
          }
        }
      });
      
      return issues;
    },
    severity: 'info',
    description: "Dynamic data structures in account definitions",
    recommendation: "Consider using fixed-size arrays or more efficient data structures to reduce compute costs.",
    category: 'resource_management'
  }
];

// Function to perform security analysis
function performSecurityAnalysis(code: string, auditType: string): {
  issues: Array<{
    check: string;
    severity: string;
    description: string;
    recommendation: string;
    category: string;
    lineNumber?: number;
    context?: string;
    details?: string;
  }>;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
} {
  const issues: Array<{
    check: string;
    severity: string;
    description: string;
    recommendation: string;
    category: string;
    lineNumber?: number;
    context?: string;
    details?: string;
  }> = [];

  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0
  };

  // Parse code structure for better analysis
  const codeContext = parseCodeStructure(code);

  // Filter checks based on audit type
  let checksToRun = SECURITY_CHECKS;
  if (auditType === 'security-focused') {
    checksToRun = SECURITY_CHECKS.filter(check => 
      check.severity === 'critical' || check.severity === 'high'
    );
  } else if (auditType === 'basic') {
    checksToRun = SECURITY_CHECKS.filter(check => 
      check.severity === 'critical' || check.severity === 'high' || check.severity === 'medium'
    );
  }

  // Run security checks with advanced analysis
  for (const check of checksToRun) {
    const checkIssues = check.analyzer(code, codeContext);
    
    checkIssues.forEach(issue => {
      issues.push({
        check: check.name,
        severity: check.severity,
        description: check.description,
        recommendation: check.recommendation,
        category: check.category,
        lineNumber: issue.line,
        context: issue.context,
        details: issue.details
      });

      summary[check.severity]++;
      summary.total++;
    });
  }

  return { issues, summary };
}

// Function to analyze code complexity
function analyzeComplexity(code: string): {
  linesOfCode: number;
  functions: number;
  cyclomaticComplexity: number;
  nestingDepth: number;
} {
  const lines = code.split('\n').filter(line => line.trim() && !line.trim().startsWith('//'));
  const functions = (code.match(/fn\s+\w+/g) || []).length;
  
  // Simple cyclomatic complexity (count decision points)
  const decisions = (code.match(/if|while|for|match|loop|\?/g) || []).length;
  const cyclomaticComplexity = decisions + 1;
  
  // Calculate maximum nesting depth
  let currentDepth = 0;
  let maxDepth = 0;
  for (const char of code) {
    if (char === '{') {
      currentDepth++;
      maxDepth = Math.max(maxDepth, currentDepth);
    } else if (char === '}') {
      currentDepth--;
    }
  }

  return {
    linesOfCode: lines.length,
    functions,
    cyclomaticComplexity,
    nestingDepth: maxDepth
  };
}

// Enhanced MCP Tool: Generate AI Audit
server.tool(
  "generate-AI-Audit",
  "Generate a comprehensive security audit report for a Solana program",
  {
    buildId: z.string().min(1).describe("Build ID of the program to audit"),
    programAddress: z.string().optional().describe("Program address (optional, will be fetched from build if not provided)"),
    auditType: z.enum(["basic", "comprehensive", "security-focused"]).default("basic").describe("Type of audit to perform"),
    includeRecommendations: z.boolean().default(true).describe("Include security recommendations in the audit report"),
  },
  async ({ buildId, programAddress, auditType, includeRecommendations }) => {
    try {
      console.error(`🔍 Starting ${auditType} security audit for build ID: ${buildId}`);
      
      // Fetch the source code from the build
      const sourceUrl = `${API_BASE_URL}:3003/program/${buildId}/file/lib.rs`;
      console.error(`📥 Fetching source code from ${sourceUrl}...`);
      
      let sourceCode: string;
      try {
        const sourceRes = await fetch(sourceUrl);
        if (!sourceRes.ok) {
          throw new Error(`Failed to fetch source code: ${sourceRes.status} ${sourceRes.statusText}`);
        }
        sourceCode = await sourceRes.text();
      } catch (err) {
        return {
          content: [
            {
              type: "text",
              text: `❌ Failed to fetch source code for build ID ${buildId}: ${err instanceof Error ? err.message : String(err)}\n\nPlease ensure the build ID is valid and the source code is available.`,
            },
          ],
        };
      }

      // Fetch IDL for additional context
      let idlData: any = null;
      try {
        const idlUrl = `${API_BASE_URL}:3003/program/${buildId}/file/idl.json`;
        const idlRes = await fetch(idlUrl);
        if (idlRes.ok) {
          idlData = await idlRes.json();
          console.error(`📝 IDL data fetched successfully`);
        }
      } catch (err) {
        console.error(`⚠️ Could not fetch IDL data: ${err instanceof Error ? err.message : String(err)}`);
      }

      // Perform security analysis
      console.error(`🔎 Performing ${auditType} security analysis...`);
      const { issues, summary } = performSecurityAnalysis(sourceCode, auditType);
      
      // Analyze code complexity
      const complexity = analyzeComplexity(sourceCode);

      // Generate audit report
      let auditReport = `# 🛡️ Solana Program Security Audit Report\n\n`;
      
      // Header information
      auditReport += `**Build ID:** ${buildId}\n`;
      if (programAddress) {
        auditReport += `**Program Address:** ${programAddress}\n`;
      }
      if (idlData?.metadata?.name) {
        auditReport += `**Program Name:** ${idlData.metadata.name}\n`;
      }
      auditReport += `**Audit Type:** ${auditType}\n`;
      auditReport += `**Generated:** ${new Date().toISOString()}\n\n`;

      // Executive Summary
      auditReport += `## 📊 Executive Summary\n\n`;
      
      let riskLevel = 'LOW';
      if (summary.critical > 0) riskLevel = 'CRITICAL';
      else if (summary.high > 0) riskLevel = 'HIGH';
      else if (summary.medium > 2) riskLevel = 'MEDIUM';
      
      auditReport += `**Overall Risk Level:** ${riskLevel}\n\n`;
      
      auditReport += `**Issues Found:**\n`;
      auditReport += `- 🔴 Critical: ${summary.critical}\n`;
      auditReport += `- 🟠 High: ${summary.high}\n`;
      auditReport += `- 🟡 Medium: ${summary.medium}\n`;
      auditReport += `- 🔵 Low: ${summary.low}\n`;
      auditReport += `- ℹ️ Info: ${summary.info}\n`;
      auditReport += `- **Total Issues:** ${summary.total}\n\n`;

      // Code Metrics
      auditReport += `## 📈 Code Metrics\n\n`;
      auditReport += `- **Lines of Code:** ${complexity.linesOfCode}\n`;
      auditReport += `- **Functions:** ${complexity.functions}\n`;
      auditReport += `- **Cyclomatic Complexity:** ${complexity.cyclomaticComplexity}\n`;
      auditReport += `- **Max Nesting Depth:** ${complexity.nestingDepth}\n\n`;

      if (idlData) {
        auditReport += `## 📝 Program Interface Analysis\n\n`;
        auditReport += `- **Instructions:** ${idlData.instructions?.length || 0}\n`;
        auditReport += `- **Accounts:** ${idlData.accounts?.length || 0}\n`;
        auditReport += `- **Types:** ${idlData.types?.length || 0}\n\n`;
        
        if (idlData.instructions && idlData.instructions.length > 0) {
          auditReport += `**Available Instructions:**\n`;
          idlData.instructions.forEach((instruction: any, index: number) => {
            auditReport += `${index + 1}. \`${instruction.name}\``;
            if (instruction.args && instruction.args.length > 0) {
              auditReport += ` (${instruction.args.length} parameters)`;
            }
            auditReport += `\n`;
          });
          auditReport += `\n`;
        }
      }

      // Security Issues Detail
      if (issues.length > 0) {
        auditReport += `## 🚨 Security Issues\n\n`;
        
        // Group issues by severity
        const groupedIssues: Record<string, typeof issues> = {};
        issues.forEach(issue => {
          if (!groupedIssues[issue.severity]) {
            groupedIssues[issue.severity] = [];
          }
          groupedIssues[issue.severity].push(issue);
        });

        // Display issues by severity (critical first)
        const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
        const severityEmojis: Record<string, string> = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🔵',
          info: 'ℹ️'
        };

        for (const severity of severityOrder) {
          if (groupedIssues[severity]) {
            auditReport += `### ${severityEmojis[severity]} ${severity.toUpperCase()} Issues\n\n`;
            
            groupedIssues[severity].forEach((issue, index) => {
              auditReport += `#### ${index + 1}. ${issue.check}\n\n`;
              auditReport += `**Category:** ${issue.category.replace('_', ' ').toUpperCase()}\n`;
              auditReport += `**Description:** ${issue.description}\n`;
              
              if (issue.context) {
                auditReport += `**Context:** ${issue.context}\n`;
              }
              
              if (issue.details) {
                auditReport += `**Details:** ${issue.details}\n`;
              }
              
              if (issue.lineNumber) {
                auditReport += `**Line:** ${issue.lineNumber}\n`;
              }
              
              if (includeRecommendations) {
                auditReport += `**Recommendation:** ${issue.recommendation}\n`;
              }
              auditReport += `\n`;
            });
          }
        }
      } else {
        auditReport += `## ✅ Security Analysis Results\n\n`;
        auditReport += `🎉 **Excellent!** No significant security issues were detected in this ${auditType} audit.\n\n`;
        
        auditReport += `**What this means:**\n`;
        auditReport += `- Your program follows Solana/Anchor security best practices\n`;
        auditReport += `- No critical vulnerabilities were found in the static analysis\n`;
        auditReport += `- The code structure appears well-organized and secure\n\n`;
        
        auditReport += `**Still recommended:**\n`;
        auditReport += `- ✅ Test thoroughly on devnet before mainnet deployment\n`;
        auditReport += `- ✅ Consider a comprehensive audit for high-value applications\n`;
        auditReport += `- ✅ Implement additional monitoring and testing\n`;
        auditReport += `- ✅ Keep dependencies up to date\n\n`;
        
        if (auditType !== 'comprehensive') {
          auditReport += `💡 **Tip:** Run a 'comprehensive' audit to check for additional optimization opportunities and best practice recommendations.\n\n`;
        }
      }

      // Recommendations section
      if (includeRecommendations && issues.length > 0) {
        auditReport += `## 💡 General Recommendations\n\n`;
        
        if (summary.critical > 0 || summary.high > 0) {
          auditReport += `**🚨 Immediate Actions Required:**\n`;
          auditReport += `- Address all critical and high-severity issues before deployment\n`;
          auditReport += `- Implement proper access controls and input validation\n`;
          auditReport += `- Add comprehensive error handling\n\n`;
        }
        
        auditReport += `**🔒 Security Best Practices:**\n`;
        auditReport += `- Always validate account ownership and signatures\n`;
        auditReport += `- Use checked arithmetic operations\n`;
        auditReport += `- Implement the checks-effects-interactions pattern\n`;
        auditReport += `- Add account discriminators to prevent type confusion\n`;
        auditReport += `- Ensure accounts are rent-exempt\n`;
        auditReport += `- Test thoroughly on devnet before mainnet deployment\n\n`;
        
        auditReport += `**⚡ Performance Optimizations:**\n`;
        auditReport += `- Remove debug statements and TODO comments\n`;
        auditReport += `- Consider using more efficient data structures\n`;
        auditReport += `- Optimize for lower compute costs\n\n`;
      }

      // Footer
      auditReport += `## ⚠️ Audit Limitations\n\n`;
      auditReport += `This automated audit provides a baseline security analysis but has limitations:\n\n`;
      auditReport += `- **Static Analysis Only:** This audit only analyzes the source code statically\n`;
      auditReport += `- **Pattern-Based:** Detection is based on known patterns and may miss novel vulnerabilities\n`;
      auditReport += `- **No Runtime Analysis:** Does not include dynamic testing or fuzzing\n`;
      auditReport += `- **Human Review Recommended:** A manual security review by experts is still recommended\n\n`;
      auditReport += `**For production deployments, consider:**\n`;
      auditReport += `- Professional security audit by blockchain security firms\n`;
      auditReport += `- Comprehensive testing including edge cases\n`;
      auditReport += `- Bug bounty programs\n`;
      auditReport += `- Gradual rollout and monitoring\n\n`;
      
      auditReport += `---\n`;
      auditReport += `*Generated by Solana Builder Octo MCP - AI Security Audit Tool*`;

      return {
        content: [
          {
            type: "text",
            text: auditReport,
          },
        ],
      };

    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: `❌ Failed to generate audit: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
);

// MCP Tool: Deploy Solana Program
server.tool(
  "deploy-solana-program",
  "Deploy a Solana program with an existing build ID",
  {
    buildId: z.string().min(1).describe("Build ID of the previously built program"),
    cluster: z.enum(["devnet", "mainnet"]).default(defaultCluster).describe("Solana cluster to deploy to"),
    wallet: z.object({
      publicKey: z.string().optional(),
      secretKey: z.union([z.array(z.number()), z.string()]),
    }).optional().describe("Wallet keypair for deployment (uses default wallet if not provided)"),
  },
  async ({ buildId, cluster, wallet }) => {
    try {
      // Use the provided wallet or fall back to default wallet
      const deploymentWallet = wallet || defaultWallet;
      
      // Log deployment information
      console.error(`🚀 Deploying program with build ID ${buildId} to ${cluster} cluster`);
      console.error(`⏱️ Timeout set to 4 minutes (240 seconds)`);
      
      // Log which wallet we're using
      if (wallet) {
        console.error(`🔑 Using wallet provided in request`);
      } else if (deploymentWallet) {
        console.error(`🔑 Using default wallet from configuration`);
      } else {
        console.error(`⚠️ No wallet provided, a new one will be generated by the server`);
      }
      
      // Prepare the deployment request
      const deployData = {
        buildId,
        cluster,
        solanaKey: deploymentWallet,
        // No programKey - let the server generate one automatically
      };

      console.error(`🚀 Sending deploy request to ${SOLANA_DEPLOY_ENDPOINT}...`);

      // Create AbortController for 4 minute timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => {
        console.error(`⏱️ Deployment timeout after 4 minutes`);
        controller.abort();
      }, 240000); // 4 minutes = 240,000 milliseconds

      let res;
      let responseData: DeployResponse;

      try {
        // Make request with 4 minute timeout
        res = await fetch(SOLANA_DEPLOY_ENDPOINT, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(deployData),
          signal: controller.signal,
        });

        // Clear timeout if request completes successfully
        clearTimeout(timeoutId);
        console.error(`✅ Request completed before timeout`);

        responseData = await res.json() as DeployResponse;

      } catch (error) {
        // Clear timeout in case of error
        clearTimeout(timeoutId);
        
        // Handle timeout specifically
        if (error instanceof Error && error.name === 'AbortError') {
          return {
            content: [
              {
                type: "text" as const,
                text: `⏱️ Deployment timeout after 4 minutes.\n\n` +
                      `This doesn't necessarily mean the deployment failed - Solana deployments can take time.\n\n` +
                      `What to do next:\n` +
                      `1. Wait a few more minutes and check if the program appears on the explorer\n` +
                      `2. Use the fetch-program-files tool to verify if deployment succeeded\n` +
                      `3. Check the Solana explorer for recent transactions\n` +
                      `4. If needed, try deploying again\n\n` +
                      `Build ID: ${buildId}\n` +
                      `Cluster: ${cluster}\n\n` +
                      `💡 Some deployments may still succeed even after timeout.`,
              },
            ],
          };
        }
        
        // Handle other network/fetch errors
        if (error instanceof Error && error.message.includes('fetch')) {
          return {
            content: [
              {
                type: "text" as const,
                text: `🌐 Network error during deployment: ${error.message}\n\n` +
                      `This could be due to:\n` +
                      `1. Network connectivity issues\n` +
                      `2. Server overload\n` +
                      `3. Temporary service unavailability\n\n` +
                      `Please try again in a few minutes.`,
              },
            ],
          };
        }
        
        // Re-throw other errors to be handled by outer catch
        throw error;
      }

      if (!res.ok) {
        const errorRes = responseData as DeployError;
        return {
          content: [
            {
              type: "text" as const,
              text: `❌ Failed to deploy Solana program: ${errorRes.error}\n${errorRes.details ? JSON.stringify(errorRes.details, null, 2) : ''}`,
            },
          ],
        };
      }

      const successRes = responseData as DeploySuccess;
      
      // Format the successful response
      let resultText = `✅ Solana program deployed successfully to ${cluster}!\n\n`;
      
      resultText += `Program ID: ${successRes.programId}\n`;
      
      if (successRes.usedSize) {
        resultText += `Used transaction size: ${successRes.usedSize} bytes\n`;
      }
      
      if (successRes.programSizeBytes) {
        resultText += `Program binary size: ${successRes.programSizeBytes} bytes\n`;
      }
      
      if (successRes.containerUsed) {
        resultText += `Container used: ${successRes.containerUsed}\n`;
      }
      
      // Extract signature from raw output if available
      if (successRes.raw) {
        const signatureMatch = successRes.raw.match(/Signature: ([A-Za-z0-9]+)/);
        if (signatureMatch && signatureMatch[1]) {
          resultText += `\nTransaction signature: ${signatureMatch[1]}\n`;
          
          // Add link to view transaction on explorers
          resultText += `View transaction: https://${cluster === "mainnet" ? "" : `${cluster}.`}explorer.solana.com/tx/${signatureMatch[1]}\n`;
        }
      }
      
      // Add links to block explorers
      resultText += `\n${generateExplorerLinks(successRes.programId, cluster)}\n`;
      
      // Add notes about wallet source
      if (!wallet && !defaultWallet) {
        resultText += `\n📝 A wallet key was auto-generated for this deployment.`;
      } else if (!wallet && defaultWallet) {
        resultText += `\n📝 Used default wallet ${defaultWallet.publicKey ? `with public key: ${defaultWallet.publicKey}` : 'from configuration'} for deployment.`;
      }
      
      resultText += `\n📝 A program key was auto-generated, resulting in program ID: ${successRes.programId}`;
      
      // Add instructions for next steps
      resultText += `\n\n✨ Your Solana program is now live on ${cluster}! You can interact with it using the program ID.`;

      return {
        content: [
          {
            type: "text" as const,
            text: resultText,
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `❌ Failed to deploy Solana program: ${err instanceof Error ? err.message : String(err)}\n\n` +
                `If this was a timeout error, the deployment might still be processing.\n` +
                `Check the Solana explorer or try the fetch-program-files tool to verify.`,
          },
        ],
      };
    }
  }
);


// Define interface for file information response
interface FileInfoResponse {
  uuid: string;
  programId?: string;
  files: {
    idl?: {
      name: string;
      size: number;
      lastModified: string;
      url: string;
    };
    source?: {
      name: string;
      size: number;
      lastModified: string;
      url: string;
    };
    program?: {
      name: string;
      size: number;
      lastModified: string;
      url: string;
    };
  };
}

// Define interface for fetched file
interface FetchedFile {
  type: string;
  name: string;
  content: string;
  url: string;
  size?: number;
}

// Define interface for failed file
interface FailedFile {
  type: string;
  name: string;
  error: string;
}

// MCP Tool: Fetch Program Files with Direct Download Links
server.tool(
  "fetch-program-files",
  "Fetch program files (lib.rs, program.so, idl.json) for a specific build ID",
  {
    buildId: z.string().min(1).describe("Build ID of the program to fetch files for"),
    downloadOnly: z.boolean().default(false).describe("If true, only show download links without fetching file contents"),
  },
  async ({ buildId, downloadOnly }) => {
    try {
      // First, check if the build ID exists by fetching file information
      const fileInfoUrl = `${API_BASE_URL}:3003/program/${buildId}/files`;
      console.error(`🔍 Checking build ID ${buildId} at ${fileInfoUrl}...`);
      
      const fileInfoRes = await fetch(fileInfoUrl);
      
      if (!fileInfoRes.ok) {
        return {
          content: [
            {
              type: "text" as const,
              text: `❌ Failed to find build ID: ${buildId}. The build may not exist or the server may be unreachable.`,
            },
          ],
        };
      }
      
      const fileInfo = await fileInfoRes.json() as FileInfoResponse;
      console.error(`✅ Found build with ID ${buildId}, contains ${Object.keys(fileInfo.files).length} files`);
      
      // Create direct download URLs for each file
      const directUrls = {
        source: fileInfo.files.source ? `${API_BASE_URL}:3003/program/${buildId}/file/${fileInfo.files.source.name}` : null,
        program: fileInfo.files.program ? `${API_BASE_URL}:3003/program/${buildId}/file/${fileInfo.files.program.name}` : null,
        idl: fileInfo.files.idl ? `${API_BASE_URL}:3003/program/${buildId}/file/${fileInfo.files.idl.name}` : null
      };
      
      // Track which files were successfully fetched
      const fetchedFiles: FetchedFile[] = [];
      const failedFiles: FailedFile[] = [];
      
      // Function to fetch individual file
      async function fetchFile(fileType: string, fileName: string, fileUrl: string): Promise<FetchedFile | null> {
        console.error(`📥 Fetching ${fileType} from ${fileUrl}...`);
        
        try {
          const fileRes = await fetch(fileUrl);
          
          if (!fileRes.ok) {
            console.error(`❌ Failed to fetch ${fileType}: ${fileRes.status} ${fileRes.statusText}`);
            failedFiles.push({ 
              type: fileType, 
              name: fileName, 
              error: `${fileRes.status} ${fileRes.statusText}` 
            });
            return null;
          }
          
          // Get file size from headers if available
          const contentLength = fileRes.headers.get('content-length');
          const fileSize = contentLength ? parseInt(contentLength, 10) : undefined;
          
          // Get file content
          let content: string;
          if (fileType === 'source' || fileType === 'idl') {
            // For text files, get as text
            content = await fileRes.text();
          } else {
            // For binary files, get as arrayBuffer and convert to base64
            const arrayBuffer = await fileRes.arrayBuffer();
            content = Buffer.from(arrayBuffer).toString('base64');
          }
          
          const fetchedFile: FetchedFile = { 
            type: fileType, 
            name: fileName, 
            content, 
            url: fileUrl,
            size: fileSize
          };
          
          fetchedFiles.push(fetchedFile);
          return fetchedFile;
        } catch (err) {
          const errorMessage = err instanceof Error ? err.message : String(err);
          console.error(`❌ Error fetching ${fileType}: ${errorMessage}`);
          failedFiles.push({ 
            type: fileType, 
            name: fileName, 
            error: errorMessage 
          });
          return null;
        }
      }
      
      // Prepare the file information even if we're not downloading contents
      const availableFiles: Record<string, { name: string, url: string, size?: number }> = {};
      
      if (fileInfo.files.source) {
        availableFiles.source = {
          name: fileInfo.files.source.name,
          url: directUrls.source!,
          size: fileInfo.files.source.size
        };
      }
      
      if (fileInfo.files.program) {
        availableFiles.program = {
          name: fileInfo.files.program.name,
          url: directUrls.program!,
          size: fileInfo.files.program.size
        };
      }
      
      if (fileInfo.files.idl) {
        availableFiles.idl = {
          name: fileInfo.files.idl.name,
          url: directUrls.idl!,
          size: fileInfo.files.idl.size
        };
      }
      
      // If downloadOnly is true, just return the file information without fetching contents
      if (downloadOnly) {
        let resultText = `📦 Available files for build ID: ${buildId}\n\n`;
        
        // Add program ID if available
        if (fileInfo.programId) {
          resultText += `Program ID: ${fileInfo.programId}\n\n`;
        }
        
        // Add download links for each file
        resultText += `📥 Download links:\n`;
        
        if (availableFiles.source) {
          resultText += `\n📄 Source Code (${availableFiles.source.name}) - ${formatFileSize(availableFiles.source.size)}:`;
          resultText += `\n${availableFiles.source.url}\n`;
        }
        
        if (availableFiles.program) {
          resultText += `\n⚙️ Program Binary (${availableFiles.program.name}) - ${formatFileSize(availableFiles.program.size)}:`;
          resultText += `\n${availableFiles.program.url}\n`;
        }
        
        if (availableFiles.idl) {
          resultText += `\n📝 Interface Definition (${availableFiles.idl.name}) - ${formatFileSize(availableFiles.idl.size)}:`;
          resultText += `\n${availableFiles.idl.url}\n`;
        }
        
        return {
          content: [
            {
              type: "text" as const,
              text: resultText + "\n\nTip: Use curl or wget to download these files directly, or click the links to download from your browser."
            }
          ]
        };
      }
      
      // Otherwise, fetch the actual file contents
      const filePromises: Promise<FetchedFile | null>[] = [];
      
      // Source code (lib.rs)
      if (directUrls.source) {
        filePromises.push(fetchFile('source', fileInfo.files.source!.name, directUrls.source));
      }
      
      // Program binary (program.so)
      if (directUrls.program) {
        filePromises.push(fetchFile('program', fileInfo.files.program!.name, directUrls.program));
      }
      
      // IDL (idl.json)
      if (directUrls.idl) {
        filePromises.push(fetchFile('idl', fileInfo.files.idl!.name, directUrls.idl));
      }
      
      // Wait for all file fetches to complete
      const fileResults = await Promise.all(filePromises);
      
      // Filter out null results (failed fetches)
      const files = fileResults.filter((result): result is FetchedFile => result !== null);
      
      // Create a readable summary
      let resultText = `📦 Files for build ID: ${buildId}\n\n`;
      
      // Add program ID if available
      if (fileInfo.programId) {
        resultText += `Program ID: ${fileInfo.programId}\n\n`;
      }
      
      // Summary of fetched files
      resultText += `Successfully fetched ${fetchedFiles.length} files:\n`;
      fetchedFiles.forEach(file => {
        resultText += `✅ ${file.type}: ${file.name} - ${formatFileSize(file.size)}\n`;
      });
      
      // Summary of failed files
      if (failedFiles.length > 0) {
        resultText += `\nFailed to fetch ${failedFiles.length} files:\n`;
        failedFiles.forEach(file => {
          resultText += `❌ ${file.type}: ${file.name} - ${file.error}\n`;
        });
      }
      
      // Add direct download links
      resultText += `\n📥 Direct Download Links:\n`;
      
      if (directUrls.source) {
        resultText += `\n📄 Source Code: ${directUrls.source}`;
      }
      
      if (directUrls.program) {
        resultText += `\n⚙️ Program Binary: ${directUrls.program}`;
      }
      
      if (directUrls.idl) {
        resultText += `\n📝 Interface Definition: ${directUrls.idl}`;
      }
      
      resultText += `\n\nFiles are also available for direct download from the MCP host.`;
      
      // Extract IDL information if available
      let idlInfo = '';
      const idlFile = files.find(file => file.type === 'idl');
      if (idlFile) {
        try {
          const idl = JSON.parse(idlFile.content);
          
          idlInfo += `\n\n📋 IDL Summary:`;
          idlInfo += `\n- Program Address: ${idl.address || 'N/A'}`;
          idlInfo += `\n- Name: ${idl.metadata?.name || 'N/A'}`;
          idlInfo += `\n- Instructions: ${idl.instructions?.length || 0}`;
          
          if (idl.instructions && idl.instructions.length > 0) {
            idlInfo += `\n\nAvailable Instructions:`;
            idl.instructions.forEach((instruction: any, index: number) => {
              idlInfo += `\n${index + 1}. ${instruction.name}`;
              
              if (instruction.args && instruction.args.length > 0) {
                idlInfo += ` (${instruction.args.length} args)`;
              }
            });
          }
        } catch (e) {
          const errorMessage = e instanceof Error ? e.message : String(e);
          console.error(`Error parsing IDL: ${errorMessage}`);
        }
      }
      
      // Add file content information if available
      const downloadLinks = {
        source: {
          type: "text" as const,
          text: `📄 Source Code (${fileInfo.files.source?.name || "lib.rs"})`,
          attachments: [{
            type: "file" as const,
            file_name: fileInfo.files.source?.name || "lib.rs",
            mime_type: "text/plain"
          }]
        },
        program: {
          type: "text" as const,
          text: `⚙️ Program Binary (${fileInfo.files.program?.name || "program.so"})`,
          attachments: [{
            type: "file" as const,
            file_name: fileInfo.files.program?.name || "program.so",
            mime_type: "application/octet-stream"
          }]
        },
        idl: {
          type: "text" as const,
          text: `📝 Interface Definition (${fileInfo.files.idl?.name || "idl.json"})`,
          attachments: [{
            type: "file" as const,
            file_name: fileInfo.files.idl?.name || "idl.json",
            mime_type: "application/json"
          }]
        }
      };
      
      type Attachment = {
        type: "file";
        file_name: string;
        mime_type: string;
        content: string;
        encoding?: "base64";
      };
      
      const attachments: Attachment[] = [];
      const contentBlocks = [
        {
          type: "text" as const,
          text: resultText + idlInfo
        }
      ];
      
      // Add file content blocks
      files.forEach(file => {
        if (file.type === 'source') {
          attachments.push({
            type: "file",
            file_name: file.name,
            mime_type: "text/plain",
            content: file.content
          });
          contentBlocks.push(downloadLinks.source);
        } else if (file.type === 'program') {
          attachments.push({
            type: "file",
            file_name: file.name,
            mime_type: "application/octet-stream",
            content: file.content,
            encoding: "base64"
          });
          contentBlocks.push(downloadLinks.program);
        } else if (file.type === 'idl') {
          attachments.push({
            type: "file",
            file_name: file.name,
            mime_type: "application/json",
            content: file.content
          });
          contentBlocks.push(downloadLinks.idl);
        }
      });
      
      return {
        content: contentBlocks,
        attachments: attachments
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `❌ Failed to fetch program files: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
);


// MCP Tool: Build UI for deployed Solana program
server.tool(
  "build-ui",
  "Generate a link to a frontend UI for an already deployed Solana program",
  {
    buildId: z.string().min(1).describe("Build ID of the previously built program"),
    programAddress: z.string().min(1).describe("Program address (ID) of the deployed program"),
    cluster: z.enum(["devnet", "mainnet"]).default("devnet").describe("Solana cluster the program is deployed to"),
    templateRepo: z.string().default("https://github.com/octonetai/Solana-Dapp.git").describe("Git repository template to use for the UI"),
    gitpodBaseUrl: z.string().default("https://octo.up.railway.app").describe("Base URL for the Gitpod workspace"),
  },
  async ({ buildId, programAddress, cluster, templateRepo, gitpodBaseUrl }) => {
    try {
      // Validate input parameters
      if (!buildId || !programAddress) {
        return {
          content: [
            {
              type: "text",
              text: "❌ Both buildId and programAddress are required to generate a UI link.",
            },
          ],
        };
      }
      
      // Generate the UI link using the provided parameters
      const uiLink = `${gitpodBaseUrl}/git?url=${encodeURIComponent(templateRepo)}&id=${encodeURIComponent(buildId)}&pa=${encodeURIComponent(programAddress)}`;
      
      // Fetch IDL to include in the response
      const idlUrl = `${API_BASE_URL}:3003/program/${buildId}/file/idl.json`;
      let idlContent: any = null;
      
      console.error(`🔍 Fetching IDL for build ID ${buildId} at ${idlUrl}...`);
      
      try {
        const idlRes = await fetch(idlUrl);
        if (idlRes.ok) {
          idlContent = await idlRes.json();
        }
      } catch (err) {
        console.error(`⚠️ Warning: Could not fetch IDL: ${err instanceof Error ? err.message : String(err)}`);
      }
      
      // Generate a detailed response
      let resultText = `✅ Frontend UI generation request successful!\n\n`;
      resultText += `🔗 Your UI is ready at:\n${uiLink}\n\n`;
      
      resultText += `📋 Project Details:\n`;
      resultText += `• Build ID: ${buildId}\n`;
      resultText += `• Program Address: ${programAddress}\n`;
      resultText += `• Cluster: ${cluster}\n`;
      resultText += `• Template: ${templateRepo}\n\n`;
      
      // Add explorer links
      resultText += `${generateExplorerLinks(programAddress, cluster)}\n\n`;
      
      // Add IDL summary if available
      if (idlContent) {
        resultText += `📝 IDL Summary:\n`;
        
        if (idlContent.metadata?.name) {
          resultText += `• Program Name: ${idlContent.metadata.name}\n`;
        }
        
        if (idlContent.instructions) {
          resultText += `• Instructions: ${idlContent.instructions.length}\n`;
          
          // List the available instructions
          resultText += `\nAvailable Instructions:\n`;
          idlContent.instructions.forEach((instruction: any, index: number) => {
            resultText += `${index + 1}. ${instruction.name}`;
            
            if (instruction.args && instruction.args.length > 0) {
              resultText += ` (${instruction.args.length} args)`;
              
              // If fewer than 5 args, list them
              if (instruction.args.length < 5) {
                const argNames = instruction.args.map((arg: any) => arg.name).join(", ");
                resultText += `: ${argNames}`;
              }
            }
            
            resultText += `\n`;
          });
        }
      }
      
      // Add instructions for next steps
      resultText += `\n🚀 Next Steps:\n`;
      resultText += `1. Click the UI link above to open your Solana dApp frontend\n`;
      resultText += `2. The frontend is pre-configured to connect to your program at address: ${programAddress}\n`;
      resultText += `3. You can customize the UI by editing the code in the Gitpod workspace\n`;
      resultText += `4. Connect your wallet in the UI to interact with your deployed program\n\n`;
      
      resultText += `Note: This UI is running in a temporary Gitpod workspace. To create a permanent deployment, fork the repository and deploy to Vercel, Netlify, or another hosting provider.`;
      
      return {
        content: [
          {
            type: "text",
            text: resultText,
          },
        ],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text",
            text: `❌ Failed to generate UI: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
      };
    }
  }
);

// Helper function to format file sizes in a human-readable way
function formatFileSize(sizeInBytes?: number): string {
  if (sizeInBytes === undefined) return "Unknown size";
  
  if (sizeInBytes < 1024) {
    return `${sizeInBytes} bytes`;
  } else if (sizeInBytes < 1024 * 1024) {
    return `${(sizeInBytes / 1024).toFixed(1)} KB`;
  } else if (sizeInBytes < 1024 * 1024 * 1024) {
    return `${(sizeInBytes / (1024 * 1024)).toFixed(1)} MB`;
  } else {
    return `${(sizeInBytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }
}

// Start the MCP server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("📡 Solana Builder MCP Server is running with build, validate, and deploy tools...");
}

main().catch((err) => {
  console.error("❌ Fatal error in Solana Builder:", err);
  process.exit(1);
});
