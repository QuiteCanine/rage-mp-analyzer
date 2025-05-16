/**
 * RAGE MP Server Code Analyzer
 * A complete all-in-one script for analyzing GTA RAGE MP server repositories
 * 
 * Usage:
 * - Install Node.js
 * - Save this file as rage-mp-analyzer.js
 * - Run: node rage-mp-analyzer.js /path/to/your/repo
 * 
 * This script will analyze your RAGE MP server code and generate a detailed report
 * on code quality, structure, performance, security, game mechanics, and integration.
 */

const fs = require('fs');
const path = require('path');
const util = require('util');

// Promisify fs functions
const readdir = util.promisify(fs.readdir);
const stat = util.promisify(fs.stat);
const readFile = util.promisify(fs.readFile);
const writeFile = util.promisify(fs.writeFile);
const mkdir = util.promisify(fs.mkdir);

/**
 * RAGE MP Patterns and Best Practices
 */
const RAGE_PATTERNS = {
    // RAGE MP native function patterns
    nativeFunctions: {
        client: [
            'mp.players', 'mp.vehicles', 'mp.objects', 'mp.blips', 'mp.markers',
            'mp.events', 'mp.game', 'mp.gui', 'mp.keys', 'mp.nametags', 'mp.storage'
        ],
        server: [
            'mp.players', 'mp.vehicles', 'mp.objects', 'mp.blips', 'mp.markers',
            'mp.events', 'mp.world', 'mp.config'
        ]
    },
    
    // Common event patterns
    commonEvents: {
        client: [
            'render', 'click', 'playerJoin', 'playerQuit', 'playerDeath', 'playerChat',
            'playerEnterVehicle', 'playerExitVehicle', 'playerWeaponChange', 'playerStreamIn', 'playerStreamOut'
        ],
        server: [
            'playerJoin', 'playerQuit', 'playerDeath', 'playerChat', 'playerEnterVehicle',
            'playerExitVehicle', 'playerWeaponChange', 'playerSpawn', 'vehicleDestroy', 'playerCommand'
        ]
    },
    
    // Best practices for RAGE MP development
    bestPractices: {
        structure: [
            'Separate client and server code',
            'Organize resources by functionality',
            'Use modular architecture',
            'Keep configuration files separate',
            'Implement proper error handling'
        ],
        codeQuality: [
            'Avoid global variables',
            'Use descriptive variable and function names',
            'Add proper comments for complex code',
            'Keep functions small and focused',
            'Use consistent coding style'
        ],
        performance: [
            'Minimize network traffic',
            'Use efficient data structures',
            'Avoid creating entities in loops',
            'Cache frequently used values',
            'Use connection pooling for databases'
        ],
        security: [
            'Validate all client inputs on server',
            'Use parameterized queries for database',
            'Implement proper permission checks',
            'Avoid exposing sensitive information',
            'Log security-related events'
        ]
    },
    
    // Security vulnerabilities in RAGE MP
    securityVulnerabilities: {
        clientSideValidationOnly: /if\s*\([^)]*\)\s*{\s*mp\.events\.callRemote\(/g,
        unsafeCommandExecution: /mp\.events\.addCommand\(['"`](\w+)['"`],\s*function\s*\([^)]*\)\s*{[^}]*(?:\.(?:spawn|position|model|dimension|health|armor)\s*=|\.(?:giveWeapon|setVariable|setClothes|setHeadBlend)\()/g,
        sqlInjection: /(?:db|con|connection|mysql)\.query\(['"`][^'"`]*(?:\+\s*(?![\?])[\w.]+|\$\{)/g,
        hardcodedCredentials: /(?:password|pass|pwd|passwd|secret|key|token|auth)\s*(?:=|:)\s*['"`][A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{4,}['"`]/gi
    }
};

/**
 * Code Quality Analysis Patterns
 */
const CODE_QUALITY_PATTERNS = {
    // Code smells
    directEval: /\beval\s*\(/g,
    uselessConsoleLog: /console\.log\(['"](?:test|testing|debug|here|asdf|foo|bar)['"]\)/g,
    hardcodedIPs: /\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    todoComments: /\/\/\s*TODO|\*\s*TODO|\/\*\s*TODO/gi,
    magicNumbers: /(?<!\w)(?<!\.)[0-9]{4,}(?!\w|\.)/g, // Look for 4+ digit numbers
    
    // RAGE MP specific patterns
    globalVarLeak: /^(?!const |let |var |function )\w+\s*=[^=]/gm,
    nestedCallbacks: /\b(function\s*\([^)]*\)\s*{[^}]*){3,}/g, // Look for deeply nested callbacks

    // General code quality
    emptyTryCatch: /try\s*{[^}]*}\s*catch\s*\([^)]+\)\s*{\s*}/g,
    longFunctions: /function\s+\w+\s*\([^)]*\)\s*{(?:[^{}]|{[^{}]*})*{(?:[^{}]|{[^{}]*})*{[^{}]*}[^{}]*}[^{}]*}/g, // Look for deeply nested function blocks
};

/**
 * Performance Analysis Patterns
 */
const PERFORMANCE_PATTERNS = {
    // Server-side patterns
    globalScopedVariables: /^(?:var|let|const)?\s*(\w+)\s*=(?!\s*function)/gm,
    
    // Inefficient loops
    forInLoops: /for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+/g,
    arrayForLoops: /for\s*\(\s*(?:var|let|const)?\s*\w+\s*=\s*0;\s*\w+\s*<\s*(\w+)\.length/g,
    
    // Function performance issues
    recursiveFunctions: /function\s+(\w+)[^{]*{[^}]*\1\s*\(/g,
    functionCreationInLoop: /for\s*\([^{]*{\s*(?:[^{}]|{[^{}]*})*function\s*\(/g,
    
    // Memory leaks and GC issues
    eventListenersNotRemoved: /mp\.events\.add\(/g,
    eventListenersRemoved: /mp\.events\.remove\(/g,
    
    // RAGE MP specific performance issues
    frequentPosGetting: /(?:player|vehicle|object)\.position/g,
    entityCreationInLoop: /for\s*\([^{]*{[^}]*new mp\.(Vehicle|Object|Blip|Checkpoint|Marker|TextLabel)/g,
    
    // Inefficient database operations
    sequentialDbQueries: /(?:db|con|connection|mysql)\.query\([^)]+\)[^;]*\n\s*(?:db|con|connection|mysql)\.query/g,
    improperQueryBuilding: /(?:db|con|connection|mysql)\.query\([^)]*\+\s*[\w.]+\s*\+/g
};

/**
 * Security Analysis Patterns
 */
const SECURITY_PATTERNS = {
    // RAGE MP specific security issues
    unsafeCommandHandling: /mp\.events\.addCommand\(['"`](\w+)['"`],\s*function\s*\([^)]*\)\s*{[^}]*(?:\.(?:spawn|position|model|dimension|health|armor)\s*=|\.(?:giveWeapon|setVariable|setClothes|setHeadBlend)\()/g,
    unsafeRemoteEvents: /mp\.events\.add\(['"`](\w+)['"`],\s*function\s*\([^)]*\)\s*{[^}]*(?:\.(?:spawn|position|model|dimension|health|armor)\s*=|\.(?:giveWeapon|setVariable|setClothes|setHeadBlend)\()/g,
    
    // General security vulnerabilities
    sqlInjection: /(?:db|con|connection|mysql)\.query\(['"`][^'"`]*(?:\+\s*(?![\?])[\w.]+|\$\{)/g,
    xssVulnerability: /\.innerHTML\s*=\s*(?!['"`]<)/g,
    jsonInjection: /JSON\.parse\(\s*.*(?:\+\s*[\w.]+|\$\{)/g,
    
    // Sensitive data exposure
    hardcodedCredentials: /(?:password|pass|pwd|passwd|secret|key|token|auth)\s*(?:=|:)\s*['"`][A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{4,}['"`]/gi,
    hardcodedApiKeys: /(?:api[_-]?key|apikey)\s*(?:=|:)\s*['"`][A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{10,}['"`]/gi,
    
    // Authentication and authorization
    weakAuthentication: /function\s+(?:login|authenticate|auth|checkPass).*{[^}]*(?:==|===).*(?:['"`]admin['"`]|['"`]password['"`]|['"`]123)/g,
    missingPermissionChecks: /function\s+(?:admin|kick|ban|give|delete|remove|update|set).*{[^}]*(?!\s*if\s*\(\s*.*?(?:admin|perm|right|access|auth|isAllowed))/g,
    
    // Network security
    insecureWebRequests: /https?:\/\/(?!localhost|127\.0\.0\.1)\S+['"`]/g
};

/**
 * RAGE MP Expected Structure
 */
const EXPECTED_DIRECTORIES = [
    'packages',
    'client_packages',
    'conf.json'
];

const RECOMMENDED_DIRECTORIES = {
    'packages': [
        'core',
        'gamemode',
        'database',
        'vehicles',
        'characters',
        'jobs',
        'admin'
    ],
    'client_packages': [
        'browser',
        'cef',
        'game_ui',
        'events'
    ]
};

/**
 * Game Mechanic Categories
 */
const MECHANIC_CATEGORIES = [
    'vehicles',
    'weapons',
    'characters',
    'inventory',
    'economy',
    'jobs',
    'housing',
    'admin',
    'chat',
    'combat',
    'factions',
    'missions',
    'customization',
    'persistence',
    'world'
];

/**
 * Main RAGE MP Server Code Analyzer Class
 */
class RageMP_Analyzer {
    constructor(repoPath) {
        this.repoPath = repoPath;
        this.fileList = [];
        this.report = {
            structure: { issues: [], strengths: [] },
            codeQuality: { issues: [], strengths: [], codeSmells: {} },
            performance: { issues: [], strengths: [], inefficientPatterns: {} },
            security: { issues: [], strengths: [], vulnerabilities: {} },
            gameMechanics: { issues: [], strengths: [], implementedMechanics: {} },
            integration: { issues: [], strengths: [] },
            summary: {},
            recommendations: []
        };
    }

    /**
     * Run full analysis on repository
     */
    async analyze() {
        console.log('Starting RAGE MP server code analysis...');
        
        // Validate repository path
        if (!fs.existsSync(this.repoPath)) {
            throw new Error(`Repository path does not exist: ${this.repoPath}`);
        }
        
        // Scan files
        this.fileList = await this.scanDirectory(this.repoPath);
        console.log(`Found ${this.fileList.length} files to analyze`);
        
        // Run analysis modules
        await this.analyzeStructure();
        await this.analyzeCodeQuality();
        await this.analyzePerformance();
        await this.analyzeSecurity();
        await this.analyzeGameMechanics();
        await this.analyzeIntegration();
        
        // Generate summary and recommendations
        this.generateSummary();
        this.generateRecommendations();
        
        return this.report;
    }
    
    /**
     * Scan directory recursively for files
     */
    async scanDirectory(dir, fileList = []) {
        try {
            const files = await readdir(dir);
            
            for (const file of files) {
                const filePath = path.join(dir, file);
                
                // Skip node_modules and hidden directories
                if (file === 'node_modules' || file.startsWith('.')) {
                    continue;
                }
                
                const fileStat = await stat(filePath);
                
                if (fileStat.isDirectory()) {
                    // Recursively scan subdirectories
                    await this.scanDirectory(filePath, fileList);
                } else {
                    fileList.push(filePath);
                }
            }
            
            return fileList;
        } catch (error) {
            console.error(`Error scanning directory ${dir}:`, error.message);
            return fileList;
        }
    }
    
    /**
     * Analyze Repository Structure
     */
    async analyzeStructure() {
        console.log('Analyzing repository structure...');
        
        // Check for essential RAGE MP directories
        for (const dir of EXPECTED_DIRECTORIES) {
            const dirPath = path.join(this.repoPath, dir);
            if (!fs.existsSync(dirPath)) {
                this.report.structure.issues.push({
                    title: `Missing core directory: ${dir}`,
                    description: `The essential RAGE MP directory '${dir}' is missing from the repository.`,
                    solution: `Create the '${dir}' directory following RAGE MP standards.`,
                    severity: 'critical',
                    category: 'structure'
                });
            }
        }
        
        // Check recommended organization
        for (const [dir, recommended] of Object.entries(RECOMMENDED_DIRECTORIES)) {
            const dirPath = path.join(this.repoPath, dir);
            
            if (!fs.existsSync(dirPath)) continue;
            
            try {
                const existingSubdirs = (await readdir(dirPath))
                    .filter(item => {
                        try {
                            return fs.statSync(path.join(dirPath, item)).isDirectory();
                        } catch (e) {
                            return false;
                        }
                    });
                
                const missingRecommended = recommended.filter(rec => !existingSubdirs.includes(rec));
                
                if (missingRecommended.length > 0) {
                    this.report.structure.issues.push({
                        title: `Recommended organization missing in ${dir}`,
                        description: `The ${dir} directory is missing recommended organizational subdirectories: ${missingRecommended.join(', ')}`,
                        solution: `Consider organizing your code by creating these subdirectories for better code organization.`,
                        severity: 'minor',
                        category: 'structure'
                    });
                } else {
                    this.report.structure.strengths.push({
                        title: `Well-organized ${dir} directory`,
                        description: `The ${dir} directory follows recommended organizational practices.`
                    });
                }
            } catch (error) {
                console.error(`Error checking directory ${dirPath}:`, error.message);
            }
        }
        
        // Evaluate module separation - check for large files
        const packagesDir = path.join(this.repoPath, 'packages');
        if (fs.existsSync(packagesDir)) {
            // Look for extremely large files which might indicate poor separation
            const largeFiles = this.fileList
                .filter(file => file.startsWith(packagesDir))
                .filter(file => {
                    try {
                        const stats = fs.statSync(file);
                        return stats.size > 100 * 1024; // Files larger than 100KB
                    } catch (error) {
                        return false;
                    }
                });
            
            if (largeFiles.length > 0) {
                this.report.structure.issues.push({
                    title: "Large files indicate poor module separation",
                    description: `Found ${largeFiles.length} files exceeding 100KB in size, which might indicate insufficient module separation.`,
                    solution: "Consider breaking down large files into smaller, focused modules with clear responsibilities.",
                    severity: "major",
                    category: "structure"
                });
                
                // Add specific file details
                largeFiles.forEach(file => {
                    const relativePath = path.relative(this.repoPath, file);
                    const stats = fs.statSync(file);
                    this.report.structure.issues.push({
                        title: `Large file: ${relativePath}`,
                        description: `File size: ${Math.round(stats.size / 1024)}KB`,
                        solution: "Break this file into smaller modules with focused responsibilities.",
                        severity: "minor",
                        category: "structure"
                    });
                });
            }
        }
        
        // Check for proper configuration management
        const configFiles = this.fileList.filter(file => {
            const filename = path.basename(file).toLowerCase();
            return filename.includes('config') || 
                   filename.includes('settings') || 
                   filename === 'conf.json';
        });
        
        if (configFiles.length === 0) {
            this.report.structure.issues.push({
                title: "Missing configuration files",
                description: "No dedicated configuration files found, which may lead to hardcoded values and difficulty maintaining the server.",
                solution: "Create dedicated configuration files to store settings separately from code logic.",
                severity: "major",
                category: "structure"
            });
        } else {
            // Check if config files contain sensitive information
            for (const configFile of configFiles) {
                try {
                    const content = await readFile(configFile, 'utf8');
                    
                    // Check for potential passwords, tokens, or API keys
                    if (
                        /password["']?\s*[:=]\s*["'][^"']+["']/i.test(content) ||
                        /apikey["']?\s*[:=]\s*["'][^"']+["']/i.test(content) ||
                        /token["']?\s*[:=]\s*["'][^"']+["']/i.test(content) ||
                        /secret["']?\s*[:=]\s*["'][^"']+["']/i.test(content)
                    ) {
                        this.report.security.issues.push({
                            title: "Sensitive information in configuration file",
                            description: `The file ${path.relative(this.repoPath, configFile)} appears to contain hardcoded credentials or sensitive information.`,
                            solution: "Move sensitive information to environment variables or a secure secrets management system.",
                            severity: "critical",
                            category: "security"
                        });
                    }
                } catch (error) {
                    console.error(`Error reading config file ${configFile}:`, error.message);
                }
            }
        }
        
        // Check for common architectural issues
        
        // 1. Mixed client and server code
        const serverFiles = this.fileList.filter(file => file.includes('/packages/'));
        const clientFiles = this.fileList.filter(file => file.includes('/client_packages/'));
        
        for (const serverFile of serverFiles.slice(0, 20)) { // Limit to first 20 files for performance
            try {
                const content = await readFile(serverFile, 'utf8');
                if (content.includes('mp.events.add') && !serverFile.includes('events')) {
                    this.report.structure.issues.push({
                        title: "Mixed client and server code",
                        description: `The server file ${path.relative(this.repoPath, serverFile)} contains client-side event handling code.`,
                        solution: "Separate client and server code properly following RAGE MP architecture.",
                        severity: "major",
                        category: "structure"
                    });
                    break; // One example is enough
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // 2. Check for disorganized resource structure
        const metaFiles = this.fileList.filter(file => path.basename(file) === 'meta.xml');
        for (const metaFile of metaFiles) {
            try {
                const dirPath = path.dirname(metaFile);
                const dirItems = await readdir(dirPath);
                
                // If the directory contains a mix of many different file types, it might be disorganized
                const fileTypes = new Set(dirItems.map(item => path.extname(item)));
                if (fileTypes.size > 5 && dirItems.length > 15) {
                    this.report.structure.issues.push({
                        title: "Potentially disorganized resource",
                        description: `The resource in ${path.relative(this.repoPath, dirPath)} contains many files of different types (${fileTypes.size} different extensions).`,
                        solution: "Consider organizing this resource into subdirectories by functionality.",
                        severity: "minor",
                        category: "structure"
                    });
                }
            } catch (error) {
                // Skip errors
            }
        }
        
        // Add overall structure evaluation
        if (this.report.structure.issues.length === 0) {
            this.report.structure.strengths.push({
                title: "Well-organized repository structure",
                description: "The repository follows RAGE MP best practices for organization."
            });
        }
        
        console.log(`Structure analysis complete. Found ${this.report.structure.issues.length} issues.`);
    }
    
    /**
     * Analyze Code Quality
     */
    async analyzeCodeQuality() {
        console.log('Analyzing code quality...');
        
        // Filter code files only
        const codeFiles = this.fileList.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.js', '.ts', '.jsx', '.tsx', '.json', '.lua'].includes(ext);
        });
        
        // Analyze each code file
        for (const file of codeFiles) {
            await this._analyzeCodeQualityFile(file);
        }
        
        // Calculate overall code quality metrics
        this._calculateCodeQualityMetrics(codeFiles.length);
        
        console.log(`Code quality analysis complete. Found ${this.report.codeQuality.issues.length} issues.`);
    }
    
    /**
     * Analyze a single file for code quality issues
     */
    async _analyzeCodeQualityFile(filePath) {
        try {
            const content = await readFile(filePath, 'utf8');
            const relativePath = path.relative(this.repoPath, filePath);
            const ext = path.extname(filePath).toLowerCase();
            
            // Skip analyzing minified files
            if (ext === '.js' && content.length > 5000 && content.split('\n').length < 50) {
                return; // Likely a minified file
            }
            
            // Check for code smells
            for (const [patternName, pattern] of Object.entries(CODE_QUALITY_PATTERNS)) {
                const matches = content.match(pattern) || [];
                
                if (matches.length > 0) {
                    this.report.codeQuality.codeSmells[patternName] = 
                        (this.report.codeQuality.codeSmells[patternName] || 0) + matches.length;
                    
                    // Add specific issues
                    switch (patternName) {
                        case 'directEval':
                            this.report.codeQuality.issues.push({
                                title: "Use of eval() detected",
                                description: `File ${relativePath} uses eval(), which is unsafe and can lead to code injection.`,
                                solution: "Replace eval() with safer alternatives like JSON.parse() or predefined functions.",
                                severity: "critical",
                                category: "code-quality"
                            });
                            break;
                        case 'hardcodedIPs':
                            this.report.codeQuality.issues.push({
                                title: "Hardcoded IP addresses",
                                description: `File ${relativePath} contains hardcoded IP addresses.`,
                                solution: "Move IP addresses to configuration files to improve maintainability.",
                                severity: "major",
                                category: "code-quality"
                            });
                            break;
                        case 'globalVarLeak':
                            this.report.codeQuality.issues.push({
                                title: "Global variable leaks",
                                description: `File ${relativePath} may have unintentional global variable leaks.`,
                                solution: "Always declare variables with const, let, or var.",
                                severity: "major",
                                category: "code-quality"
                            });
                            break;
                        case 'nestedCallbacks':
                            this.report.codeQuality.issues.push({
                                title: "Callback hell detected",
                                description: `File ${relativePath} contains deeply nested callbacks which reduce code readability.`,
                                solution: "Refactor using Promises, async/await, or break down into smaller functions.",
                                severity: "major",
                                category: "code-quality"
                            });
                            break;
                        case 'emptyTryCatch':
                            this.report.codeQuality.issues.push({
                                title: "Empty catch blocks",
                                description: `File ${relativePath} contains empty catch blocks which swallow exceptions.`,
                                solution: "Add proper error handling in catch blocks or at least log the error.",
                                severity: "major",
                                category: "code-quality"
                            });
                            break;
                        case 'longFunctions':
                            this.report.codeQuality.issues.push({
                                title: "Overly complex functions",
                                description: `File ${relativePath} contains functions with deep nesting or high complexity.`,
                                solution: "Break down complex functions into smaller, focused functions with clear responsibilities.",
                                severity: "major",
                                category: "code-quality"
                            });
                            break;
                    }
                }
            }
            
            // Check for RAGE MP specific best practices
            
            // Check for proper event handling
            if (content.includes('mp.events.add') && !content.includes('try') && content.length > 500) {
                this.report.codeQuality.issues.push({
                    title: "Missing error handling in event handlers",
                    description: `File ${relativePath} contains RAGE MP event handlers without proper error handling.`,
                    solution: "Wrap event handler code in try-catch blocks to prevent server crashes on errors.",
                    severity: "major",
                    category: "code-quality"
                });
            }
            
            // Check for inappropriate command handling
            if (
                content.includes('mp.events.addCommand') && 
                (content.includes('.destroy()') || content.includes('.kick('))
            ) {
                this.report.codeQuality.issues.push({
                    title: "Dangerous operations in command handlers",
                    description: `File ${relativePath} contains potentially destructive operations in command handlers.`,
                    solution: "Add permission checks and confirmation steps before destructive operations.",
                    severity: "major",
                    category: "code-quality"
                });
            }
            
            // Check for proper async handling
            if (content.includes('async') && !content.includes('try') && !content.includes('catch')) {
                this.report.codeQuality.issues.push({
                    title: "Unhandled async exceptions",
                    description: `File ${relativePath} contains async functions without proper error handling.`,
                    solution: "Add try-catch blocks to handle errors in async functions.",
                    severity: "major",
                    category: "code-quality"
                });
            }
            
            // Look for significant blocks of commented-out code
            const lines = content.split('\n');
            let commentedCodeBlocks = 0;
            let consecutiveComments = 0;
            
            for (const line of lines) {
                if (line.trim().startsWith('//') && line.trim().length > 10 && !line.includes('TODO')) {
                    consecutiveComments++;
                } else {
                    if (consecutiveComments >= 5) {
                        commentedCodeBlocks++;
                    }
                    consecutiveComments = 0;
                }
            }
            
            if (commentedCodeBlocks > 2) {
                this.report.codeQuality.issues.push({
                    title: "Excessive commented-out code",
                    description: `File ${relativePath} contains ${commentedCodeBlocks} blocks of commented-out code.`,
                    solution: "Remove commented-out code or move to documentation if important.",
                    severity: "minor",
                    category: "code-quality"
                });
            }
            
            // Check if mixed tab and space indentation is used
            const tabIndentation = content.match(/^\t+/gm);
            const spaceIndentation = content.match(/^ +/gm);
            
            if (tabIndentation && spaceIndentation && 
                tabIndentation.length > 5 && spaceIndentation.length > 5) {
                this.report.codeQuality.issues.push({
                    title: "Mixed indentation",
                    description: `File ${relativePath} uses both tabs and spaces for indentation.`,
                    solution: "Standardize on either tabs or spaces for indentation.",
                    severity: "minor",
                    category: "code-quality"
                });
            }
            
            // Check for large file size
            if (content.length > 2000 && content.split('\n').length > 500) {
                this.report.codeQuality.issues.push({
                    title: "Excessively large file",
                    description: `File ${relativePath} is very large (${Math.round(content.length/1024)}KB, ${content.split('\n').length} lines).`,
                    solution: "Break down large files into smaller modules with specific responsibilities.",
                    severity: "minor",
                    category: "code-quality"
                });
            }
            
        } catch (error) {
            console.error(`Error analyzing file ${filePath}:`, error.message);
        }
    }
    
    /**
     * Calculate overall code quality metrics
     */
    _calculateCodeQualityMetrics(totalFiles) {
        // If there are no critical or major issues, add a strength
        if (!this.report.codeQuality.issues.some(issue => issue.severity === 'critical')) {
            this.report.codeQuality.strengths.push({
                title: "No critical code quality issues",
                description: "The codebase doesn't exhibit any critical code quality problems."
            });
        }
        
        // Check if there are too many TODO comments
        if (this.report.codeQuality.codeSmells.todoComments && this.report.codeQuality.codeSmells.todoComments > 20) {
            this.report.codeQuality.issues.push({
                title: "Excessive TODO comments",
                description: `Found ${this.report.codeQuality.codeSmells.todoComments} TODO comments across the codebase.`,
                solution: "Address outstanding TODOs or convert them to tracked issues in your project management system.",
                severity: "minor",
                category: "code-quality"
            });
        }
        
        // Add overall issue count
        const issueCount = this.report.codeQuality.issues.length;
        const issueRatio = issueCount / totalFiles;
        
        if (issueRatio > 0.5) {
            this.report.codeQuality.issues.push({
                title: "High code quality issue density",
                description: `Found an average of ${issueRatio.toFixed(2)} code quality issues per file.`,
                solution: "Consider implementing a linter and code quality standards for your project.",
                severity: "major",
                category: "code-quality"
            });
        }
    }
    
    /**
     * Analyze Performance
     */
    async analyzePerformance() {
        console.log('Analyzing performance bottlenecks...');
        
        // Filter code files only
        const codeFiles = this.fileList.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.js', '.ts', '.jsx', '.tsx', '.lua'].includes(ext);
        });
        
        // Analyze each code file
        for (const file of codeFiles) {
            await this._analyzePerformanceFile(file);
        }
        
        // Check for resource efficiency
        await this._analyzeResourceDistribution();
        
        // Check for event handling efficiency
        await this._analyzeEventHandling(codeFiles);
        
        // Check for database usage patterns
        await this._analyzeDatabaseUsage(codeFiles);
        
        console.log(`Performance analysis complete. Found ${this.report.performance.issues.length} issues.`);
    }
    
    /**
     * Analyze a single file for performance issues
     */
    async _analyzePerformanceFile(filePath) {
        try {
            const content = await readFile(filePath, 'utf8');
            const relativePath = path.relative(this.repoPath, filePath);
            
            // Check for each performance pattern
            for (const [patternName, pattern] of Object.entries(PERFORMANCE_PATTERNS)) {
                const matches = content.match(pattern) || [];
                
                if (matches.length > 0) {
                    this.report.performance.inefficientPatterns[patternName] = 
                        (this.report.performance.inefficientPatterns[patternName] || 0) + matches.length;
                    
                    // Create specific performance issues
                    switch (patternName) {
                        case 'globalScopedVariables':
                            if (matches.length > 10) {
                                this.report.performance.issues.push({
                                    title: "Excessive use of global variables",
                                    description: `File ${relativePath} contains ${matches.length} global-scoped variables which may impact performance.`,
                                    solution: "Limit global variables and prefer local scopes to reduce memory usage and improve performance.",
                                    severity: "major",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'forInLoops':
                            if (matches.length > 3) {
                                this.report.performance.issues.push({
                                    title: "Inefficient for...in loops",
                                    description: `File ${relativePath} uses ${matches.length} for...in loops which are slower than other loop types.`,
                                    solution: "Replace for...in loops with for...of, forEach, or standard for loops where possible.",
                                    severity: "minor",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'recursiveFunctions':
                            if (matches.length > 0) {
                                this.report.performance.issues.push({
                                    title: "Potentially inefficient recursive functions",
                                    description: `File ${relativePath} contains ${matches.length} recursive function calls that might cause stack overflow.`,
                                    solution: "Ensure recursive functions have proper termination conditions and consider iterative alternatives.",
                                    severity: "major",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'functionCreationInLoop':
                            if (matches.length > 0) {
                                this.report.performance.issues.push({
                                    title: "Function creation inside loops",
                                    description: `File ${relativePath} creates function objects inside loops, which is inefficient.`,
                                    solution: "Move function declarations outside of loops to prevent repetitive function object creation.",
                                    severity: "major",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'entityCreationInLoop':
                            if (matches.length > 0) {
                                this.report.performance.issues.push({
                                    title: "Entity creation inside loops",
                                    description: `File ${relativePath} creates RAGE MP entities inside loops which can cause performance issues.`,
                                    solution: "Batch entity creation where possible or use more efficient methods for mass entity creation.",
                                    severity: "critical",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'frequentPosGetting':
                            if (matches.length > 15) {
                                this.report.performance.issues.push({
                                    title: "Excessive position property access",
                                    description: `File ${relativePath} frequently accesses position properties (${matches.length} times) which can impact performance.`,
                                    solution: "Cache position values when used multiple times in the same context.",
                                    severity: "minor",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'sequentialDbQueries':
                            if (matches.length > 0) {
                                this.report.performance.issues.push({
                                    title: "Sequential database queries",
                                    description: `File ${relativePath} contains sequential database queries that could be optimized.`,
                                    solution: "Use transactions, batch queries, or async parallel execution where appropriate.",
                                    severity: "major",
                                    category: "performance"
                                });
                            }
                            break;
                        case 'improperQueryBuilding':
                            if (matches.length > 0) {
                                this.report.security.issues.push({
                                    title: "Unsafe SQL query construction",
                                    description: `File ${relativePath} builds SQL queries using string concatenation, risking SQL injection.`,
                                    solution: "Use parameterized queries or prepared statements instead of string concatenation.",
                                    severity: "critical",
                                    category: "security"
                                });
                            }
                            break;
                    }
                }
            }
            
            // Check for computationally expensive operations
            
            // Check for nested loops
            const nestedLoops = content.match(/for\s*\([^{]*{[^}]*for\s*\([^{]*{/g) || [];
            if (nestedLoops.length > 2) {
                this.report.performance.issues.push({
                    title: "Nested loops detected",
                    description: `File ${relativePath} contains ${nestedLoops.length} nested loops which can cause O(n²) or worse complexity.`,
                    solution: "Optimize nested loops by reducing iterations or using more efficient data structures.",
                    severity: "major",
                    category: "performance"
                });
            }
            
            // Check for heavy string operations
            const heavyStringOps = content.match(/\.split\([^)]+\)|\.\replace\([^)]+\)/g) || [];
            if (heavyStringOps.length > 15) {
                this.report.performance.issues.push({
                    title: "Excessive string operations",
                    description: `File ${relativePath} contains ${heavyStringOps.length} potentially heavy string operations.`,
                    solution: "Cache results of string operations when used repeatedly.",
                    severity: "minor",
                    category: "performance"
                });
            }
            
            // Check for large array operations
            const arrayOps = content.match(/\.(map|filter|reduce|forEach|sort|some|every)\(/g) || [];
            if (arrayOps.length > 15) {
                this.report.performance.issues.push({
                    title: "Many array operations",
                    description: `File ${relativePath} contains ${arrayOps.length} array operations which may be inefficient on large arrays.`,
                    solution: "Consider optimizing array operations especially if dealing with large data sets.",
                    severity: "minor",
                    category: "performance"
                });
            }
            
            // Check for RAGE MP specific performance issues
            
            // Check for streaming area operations
            const streamingOps = content.match(/\.createPed\(|\.createVehicle\(|\.createObject\(/g) || [];
            if (streamingOps.length > 10) {
                this.report.performance.issues.push({
                    title: "Excessive entity creation",
                    description: `File ${relativePath} creates many entities (${streamingOps.length}) which may impact client performance.`,
                    solution: "Implement streaming mechanisms and only create entities when needed.",
                    severity: "major",
                    category: "performance"
                });
            }
            
            // Check for inefficient player iteration
            if (content.includes('mp.players.forEach') && content.includes('if(')) {
                this.report.performance.issues.push({
                    title: "Inefficient player filtering",
                    description: `File ${relativePath} iterates through all players with conditional checks.`,
                    solution: "Use mp.players.toArray().filter() for more efficient filtering operations.",
                    severity: "minor",
                    category: "performance"
                });
            }
            
            // Check for timer abuse
            const timers = content.match(/setTimeout\(|setInterval\(/g) || [];
            const shortTimers = content.match(/setTimeout\([^,]+,\s*[1-9][0-9]?[0-9]?\)/g) || [];
            
            if (timers.length > 10) {
                this.report.performance.issues.push({
                    title: "Excessive use of timers",
                    description: `File ${relativePath} uses ${timers.length} timers which may cause performance issues.`,
                    solution: "Consolidate timers or use alternative timing mechanisms like animation frames.",
                    severity: "minor",
                    category: "performance"
                });
            }
            
            if (shortTimers.length > 3) {
                this.report.performance.issues.push({
                    title: "Very short interval timers",
                    description: `File ${relativePath} uses ${shortTimers.length} timers with very short intervals.`,
                    solution: "Avoid timers with very short intervals as they can cause performance issues.",
                    severity: "major",
                    category: "performance"
                });
            }
            
        } catch (error) {
            console.error(`Error analyzing file performance for ${filePath}:`, error.message);
        }
    }
    
    /**
     * Analyze resource distribution and efficiency
     */
    async _analyzeResourceDistribution() {
        // Analyze how resources are distributed
        
        // Check if resources are properly separated
        const clientResources = this.fileList.filter(file => file.includes('/client_packages/'));
        const serverResources = this.fileList.filter(file => file.includes('/packages/'));
        
        if (clientResources.length > 200) {
            this.report.performance.issues.push({
                title: "Excessive client-side resources",
                description: `Found ${clientResources.length} client-side resource files which may impact client performance.`,
                solution: "Consider consolidating client resources or implementing lazy loading strategies.",
                severity: "minor",
                category: "performance"
            });
        }
        
        // Check if static resources are properly handled
        const staticResources = this.fileList.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.jpg', '.png', '.svg', '.css', '.html'].includes(ext);
        });
        
        if (staticResources.length > 100) {
            this.report.performance.issues.push({
                title: "Many static resources",
                description: `Found ${staticResources.length} static resource files which may impact loading times.`,
                solution: "Consider bundling and minifying static resources for better performance.",
                severity: "minor",
                category: "performance"
            });
        }
    }
    
    /**
     * Analyze event handling patterns
     */
    async _analyzeEventHandling(codeFiles) {
        let totalEventHandlers = 0;
        let filesWithEvents = 0;
        
        // Count total event handlers across files
        for (const file of codeFiles.slice(0, 50)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                const eventHandlers = content.match(/mp\.events\.add\(/g) || [];
                
                if (eventHandlers.length > 0) {
                    totalEventHandlers += eventHandlers.length;
                    filesWithEvents++;
                    
                    // Check for heavily event-dependent files
                    if (eventHandlers.length > 15) {
                        this.report.performance.issues.push({
                            title: "Excessive event handlers in a single file",
                            description: `File ${path.relative(this.repoPath, file)} contains ${eventHandlers.length} event handlers.`,
                            solution: "Consider organizing event handlers into logical groups or modules.",
                            severity: "minor",
                            category: "performance"
                        });
                    }
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Check if there's event handler imbalance
        if (totalEventHandlers > 100 && filesWithEvents < 10) {
            this.report.performance.issues.push({
                title: "Event handler concentration",
                description: `Found ${totalEventHandlers} event handlers concentrated in only ${filesWithEvents} files.`,
                solution: "Distribute event handlers more evenly across files based on functionality.",
                severity: "minor",
                category: "performance"
            });
        }
    }
    
    /**
     * Analyze database usage patterns
     */
    async _analyzeDatabaseUsage(codeFiles) {
        let hasDatabase = false;
        let hasDatabaseConnection = false;
        let hasPooling = false;
        let hasTransactions = false;
        
        // Check for database usage patterns across files
        for (const file of codeFiles.slice(0, 50)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for database connection
                if (
                    content.includes('mysql') || 
                    content.includes('mongodb') || 
                    content.includes('sqlite') || 
                    content.includes('database')
                ) {
                    hasDatabase = true;
                    
                    // Check for connection handling
                    if (content.includes('connect') || content.includes('createConnection')) {
                        hasDatabaseConnection = true;
                        
                        // Check for connection pooling
                        if (content.includes('createPool') || content.includes('pool')) {
                            hasPooling = true;
                        }
                    }
                    
                    // Check for transactions
                    if (
                        content.includes('beginTransaction') || 
                        content.includes('commit') || 
                        content.includes('rollback')
                    ) {
                        hasTransactions = true;
                    }
                    
                    // Check for parameterized queries
                    const sqlQueries = content.match(/(?:query|execute)\s*\(\s*['"`][^'"`]*\?/g) || [];
                    const concatenatedQueries = content.match(/(?:query|execute)\s*\(\s*['"`][^'"`]*"\s*\+/g) || [];
                    
                    if (concatenatedQueries.length > 0 && sqlQueries.length === 0) {
                        this.report.security.issues.push({
                            title: "Non-parameterized SQL queries",
                            description: `File ${path.relative(this.repoPath, file)} uses string concatenation in SQL queries which is vulnerable to SQL injection.`,
                            solution: "Use parameterized queries with placeholders (?) and bound parameters instead of string concatenation.",
                            severity: "critical",
                            category: "security"
                        });
                    }
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Add findings based on database patterns
        if (hasDatabase) {
            if (!hasPooling) {
                this.report.performance.issues.push({
                    title: "Missing database connection pooling",
                    description: "Database connections don't appear to use connection pooling, which may lead to performance issues under load.",
                    solution: "Implement connection pooling for database connections to improve performance and resource usage.",
                    severity: "major",
                    category: "performance"
                });
            } else {
                this.report.performance.strengths.push({
                    title: "Database connection pooling",
                    description: "The server uses connection pooling for database operations, which improves performance."
                });
            }
            
            if (!hasTransactions) {
                this.report.performance.issues.push({
                    title: "Missing database transactions",
                    description: "No evidence of database transactions found, which may lead to data integrity issues.",
                    solution: "Implement database transactions for operations that require atomicity or involve multiple queries.",
                    severity: "major",
                    category: "performance"
                });
            } else {
                this.report.performance.strengths.push({
                    title: "Database transactions",
                    description: "The server uses database transactions, which helps maintain data integrity."
                });
            }
        }
    }
    
    /**
     * Analyze Security
     */
    async analyzeSecurity() {
        console.log('Analyzing security vulnerabilities...');
        
        // Filter code files only
        const codeFiles = this.fileList.filter(file => {
            const ext = path.extname(file).toLowerCase();
            return ['.js', '.ts', '.jsx', '.tsx', '.json', '.lua', '.html', '.php'].includes(ext);
        });
        
        // Analyze each code file
        for (const file of codeFiles) {
            await this._analyzeSecurityFile(file);
        }
        
        // Check overall security architecture
        await this._analyzeSecurityArchitecture();
        
        // Check for sensitive file exposure
        await this._checkSensitiveFileExposure();
        
        console.log(`Security analysis complete. Found ${this.report.security.issues.length} issues.`);
    }
    
    /**
     * Analyze a single file for security issues
     */
    async _analyzeSecurityFile(filePath) {
        try {
            const content = await readFile(filePath, 'utf8');
            const relativePath = path.relative(this.repoPath, filePath);
            
            // Check for each security pattern
            for (const [patternName, pattern] of Object.entries(SECURITY_PATTERNS)) {
                const matches = content.match(pattern) || [];
                
                if (matches.length > 0) {
                    this.report.security.vulnerabilities[patternName] = 
                        (this.report.security.vulnerabilities[patternName] || 0) + matches.length;
                    
                    // Create specific security issues
                    switch (patternName) {
                        case 'sqlInjection':
                            this.report.security.issues.push({
                                title: "SQL Injection vulnerability",
                                description: `File ${relativePath} contains potential SQL injection vulnerabilities in database queries.`,
                                solution: "Use parameterized queries or prepared statements instead of string concatenation.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'xssVulnerability':
                            this.report.security.issues.push({
                                title: "Cross-site scripting (XSS) vulnerability",
                                description: `File ${relativePath} may be vulnerable to XSS attacks via unsafe innerHTML assignments.`,
                                solution: "Use textContent instead of innerHTML or implement proper input sanitization.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'jsonInjection':
                            this.report.security.issues.push({
                                title: "JSON injection vulnerability",
                                description: `File ${relativePath} may be vulnerable to JSON injection via unsafe JSON.parse().`,
                                solution: "Ensure all JSON data is validated before parsing and avoid string concatenation.",
                                severity: "major",
                                category: "security"
                            });
                            break;
                        case 'hardcodedCredentials':
                        case 'hardcodedApiKeys':
                            this.report.security.issues.push({
                                title: "Hardcoded sensitive information",
                                description: `File ${relativePath} contains hardcoded credentials or API keys.`,
                                solution: "Move sensitive data to environment variables or a secure configuration management system.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'weakAuthentication':
                            this.report.security.issues.push({
                                title: "Weak authentication mechanism",
                                description: `File ${relativePath} contains potentially insecure authentication logic.`,
                                solution: "Implement proper authentication with secure password hashing and validation.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'missingPermissionChecks':
                            this.report.security.issues.push({
                                title: "Missing permission checks",
                                description: `File ${relativePath} contains sensitive operations without proper permission validation.`,
                                solution: "Implement proper permission checks before allowing sensitive operations.",
                                severity: "major",
                                category: "security"
                            });
                            break;
                        case 'unsafeCommandHandling':
                            this.report.security.issues.push({
                                title: "Unsafe command handling",
                                description: `File ${relativePath} contains commands that may allow unauthorized actions.`,
                                solution: "Add proper permission checks and validation to all command handlers.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'unsafeRemoteEvents':
                            this.report.security.issues.push({
                                title: "Unsafe remote event handling",
                                description: `File ${relativePath} contains remote events that may allow unauthorized actions.`,
                                solution: "Add proper validation and permission checks to all remote event handlers.",
                                severity: "critical",
                                category: "security"
                            });
                            break;
                        case 'insecureWebRequests':
                            this.report.security.issues.push({
                                title: "Potentially insecure HTTP requests",
                                description: `File ${relativePath} contains non-HTTPS URLs or insecure request patterns.`,
                                solution: "Use HTTPS for all external requests and implement proper request validation.",
                                severity: "major",
                                category: "security"
                            });
                            break;
                    }
                }
            }
            
            // Check for RAGE MP specific security issues
            
            // Check for privilege escalation in admin systems
            if (
                (relativePath.includes('admin') || content.includes('isAdmin')) && 
                content.includes('mp.events.add') &&
                !content.includes('getVariable') &&
                !content.includes('checkPermission')
            ) {
                this.report.security.issues.push({
                    title: "Potential privilege escalation in admin system",
                    description: `File ${relativePath} appears to handle admin functionality without proper permission verification.`,
                    solution: "Implement server-side permission checks for all admin functionality.",
                    severity: "critical",
                    category: "security"
                });
            }
            
            // Check for variable spoofing vulnerability
            if (content.includes('mp.players.local.getVariable(') && content.includes('mp.events.callRemote(')) {
                this.report.security.issues.push({
                    title: "Potential client variable spoofing",
                    description: `File ${relativePath} may be vulnerable to client variable spoofing.`,
                    solution: "Always verify client data on the server side and don't trust client-provided values.",
                    severity: "major",
                    category: "security"
                });
            }
            
            // Check for event handler with input validation
            const eventHandlers = content.match(/mp\.events\.add\(['"`](\w+)['"`],\s*function\s*\([^)]*\)\s*{/g) || [];
            const eventsWithValidation = content.match(/mp\.events\.add\(['"`](\w+)['"`][\s\S]*?if\s*\([^)]*(?:typeof|instanceof|===|!==|==|!=|>|<|>=|<=)/g) || [];
            
            if (eventHandlers.length > 3 && eventsWithValidation.length < eventHandlers.length / 2) {
                this.report.security.issues.push({
                    title: "Insufficient input validation in event handlers",
                    description: `File ${relativePath} contains event handlers that may lack proper input validation.`,
                    solution: "Add type checking and validation for all parameters received in event handlers.",
                    severity: "major",
                    category: "security"
                });
            }
            
        } catch (error) {
            console.error(`Error analyzing security for file ${filePath}:`, error.message);
        }
    }
    
    /**
     * Analyze overall security architecture
     */
    async _analyzeSecurityArchitecture() {
        // Analyze overall security architecture and practices
        
        // Check for proper separation of client and server code
        const clientFiles = this.fileList.filter(file => file.includes('/client_packages/'));
        const serverFiles = this.fileList.filter(file => file.includes('/packages/'));
        
        // Check if server-side files are accessible from client
        const clientAccessibleServerFiles = serverFiles.filter(file => {
            const relativePath = path.relative(this.repoPath, file);
            return !relativePath.startsWith('packages/core/') && 
                   !relativePath.startsWith('packages/protected/');
        });
        
        if (clientAccessibleServerFiles.length > 0 && serverFiles.length > 0) {
            this.report.security.issues.push({
                title: "Poor separation of client and server code",
                description: "Server-side code may be accessible to clients due to improper directory structure.",
                solution: "Create clear separation between client and server code with proper access controls.",
                severity: "major",
                category: "security"
            });
        }
        
        // Check for proper error handling that doesn't expose internals
        let errorHandlingIssues = 0;
        
        for (const file of [...clientFiles, ...serverFiles].slice(0, 20)) { // Sample up to 20 files
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for proper error handling
                const tryCatchBlocks = content.match(/try\s*{[^}]*}\s*catch\s*\(\s*(?:e|err|error)\s*\)\s*{[^}]*}/g) || [];
                const poorErrorHandling = content.match(/catch\s*\(\s*(?:e|err|error)\s*\)\s*{[^}]*console\.(?:log|error)\s*\(\s*(?:e|err|error)\s*\)/g) || [];
                
                // If there are try-catch blocks but they just log the full error, it's a potential info leak
                if (tryCatchBlocks.length > 0 && poorErrorHandling.length > 0) {
                    errorHandlingIssues++;
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        if (errorHandlingIssues > 3) {
            this.report.security.issues.push({
                title: "Information leakage through error handling",
                description: "Error handling may expose sensitive information by directly outputting error details.",
                solution: "Implement proper error handling that logs details server-side but returns safe messages to clients.",
                severity: "major",
                category: "security"
            });
        }
    }
    
    /**
     * Check for sensitive file exposure
     */
    async _checkSensitiveFileExposure() {
        // Check for sensitive files that might be exposed
        
        const sensitiveFiles = this.fileList.filter(file => {
            const filename = path.basename(file).toLowerCase();
            return filename.includes('config') || 
                   filename.includes('secret') || 
                   filename.includes('password') || 
                   filename.includes('credentials') ||
                   filename.includes('.env') ||
                   filename.includes('private');
        });
        
        // Check if these files are in client-accessible directories
        const exposedSensitiveFiles = sensitiveFiles.filter(file => 
            file.includes('/client_packages/') || 
            file.includes('/client/') || 
            file.includes('/public/')
        );
        
        if (exposedSensitiveFiles.length > 0) {
            this.report.security.issues.push({
                title: "Sensitive files exposed to clients",
                description: `Found ${exposedSensitiveFiles.length} sensitive files in client-accessible directories.`,
                solution: "Move sensitive configuration and credential files to server-side directories not accessible to clients.",
                severity: "critical",
                category: "security"
            });
            
            // Add details for each exposed file
            exposedSensitiveFiles.forEach(file => {
                this.report.security.issues.push({
                    title: `Exposed sensitive file: ${path.basename(file)}`,
                    description: `The file ${path.relative(this.repoPath, file)} may contain sensitive information and is accessible to clients.`,
                    solution: "Move this file to a server-side directory not accessible to clients.",
                    severity: "major",
                    category: "security"
                });
            });
        }
    }
    
    /**
     * Analyze Game Mechanics
     */
    async analyzeGameMechanics() {
        console.log('Analyzing game mechanics...');
        
        // Initialize mechanics tracking
        MECHANIC_CATEGORIES.forEach(category => {
            this.report.gameMechanics.implementedMechanics[category] = {
                found: false,
                evidence: [],
                files: 0,
                complexity: 0
            };
        });
        
        // Scan for mechanics
        await this._scanForMechanics();
        
        // Analyze core systems
        await this._analyzeVehicleSystems();
        await this._analyzeWeaponSystems();
        await this._analyzeCharacterSystems();
        
        console.log(`Game mechanics analysis complete. Found ${this.report.gameMechanics.issues.length} issues.`);
    }
    
    /**
     * Scan for implemented game mechanics
     */
    async _scanForMechanics() {
        // Scan for directories or files indicating specific mechanics
        for (const category of MECHANIC_CATEGORIES) {
            // Check for dedicated directories
            const categoryDirs = this.fileList.filter(file => {
                const parts = file.split('/');
                return parts.some(part => 
                    part.toLowerCase() === category || 
                    part.toLowerCase().includes(category)
                );
            });
            
            if (categoryDirs.length > 0) {
                this.report.gameMechanics.implementedMechanics[category].found = true;
                this.report.gameMechanics.implementedMechanics[category].files = categoryDirs.length;
                this.report.gameMechanics.implementedMechanics[category].evidence.push(
                    `Found ${categoryDirs.length} files/directories related to ${category}`
                );
            }
            
            // Check file content for related code
            let filesWithContent = 0;
            for (const file of this.fileList.slice(0, 100)) { // Limit for performance
                try {
                    if (path.extname(file).match(/\.(js|ts|json|lua|cs)$/i)) {
                        const content = await readFile(file, 'utf8');
                        
                        // Look for class names, function names, or comments indicating this mechanic
                        const regex = new RegExp(`(class|function|interface|// *|/\\* *).*${category}.*`, 'i');
                        
                        if (regex.test(content)) {
                            filesWithContent++;
                            
                            // Estimate complexity by code size and pattern occurrences
                            const categoryMentions = (content.match(new RegExp(category, 'gi')) || []).length;
                            const codeSize = content.length;
                            this.report.gameMechanics.implementedMechanics[category].complexity += 
                                Math.min(10, Math.floor(codeSize / 1000)) + categoryMentions;
                        }
                    }
                } catch (error) {
                    // Skip file read errors
                }
            }
            
            if (filesWithContent > 0) {
                this.report.gameMechanics.implementedMechanics[category].found = true;
                this.report.gameMechanics.implementedMechanics[category].files += filesWithContent;
                this.report.gameMechanics.implementedMechanics[category].evidence.push(
                    `Found ${filesWithContent} files with code related to ${category}`
                );
            }
        }
        
        // Add overall mechanics findings
        const implementedCount = Object.values(this.report.gameMechanics.implementedMechanics)
            .filter(m => m.found).length;
        
        if (implementedCount <= 3) {
            this.report.gameMechanics.issues.push({
                title: "Limited game mechanics implementation",
                description: `Only ${implementedCount} out of ${MECHANIC_CATEGORIES.length} core game mechanics appear to be implemented.`,
                solution: "Consider implementing more game mechanics to create a more complete gameplay experience.",
                severity: "minor",
                category: "game-mechanics"
            });
        } else if (implementedCount >= 10) {
            this.report.gameMechanics.strengths.push({
                title: "Comprehensive game mechanics",
                description: `Found ${implementedCount} different game mechanics implemented in the codebase.`
            });
        }
    }
    
    /**
     * Analyze vehicle systems
     */
    async _analyzeVehicleSystems() {
        if (!this.report.gameMechanics.implementedMechanics.vehicles.found) return;
        
        const vehicleFiles = this.fileList.filter(file => {
            return file.toLowerCase().includes('vehicle') || 
                   file.toLowerCase().includes('car') ||
                   file.toLowerCase().includes('garage');
        });
        
        if (vehicleFiles.length === 0) return;
        
        // Check vehicle features
        let hasVehicleSpawning = false;
        let hasVehicleSaving = false;
        let hasVehicleCustomization = false;
        let hasFuelSystem = false;
        let hasDamageSystem = false;
        
        for (const file of vehicleFiles.slice(0, 20)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for vehicle spawning
                if (content.includes('createVehicle') || content.includes('new mp.Vehicle')) {
                    hasVehicleSpawning = true;
                }
                
                // Check for vehicle saving
                if ((content.includes('save') || content.includes('database')) && 
                    (content.includes('vehicle') || content.includes('car'))) {
                    hasVehicleSaving = true;
                }
                
                // Check for vehicle customization
                if (content.includes('vehicleMod') || content.includes('setMod') || 
                    content.includes('customization') || content.includes('tuning')) {
                    hasVehicleCustomization = true;
                }
                
                // Check for fuel system
                if (content.includes('fuel') || content.includes('gas') || content.includes('petrol')) {
                    hasFuelSystem = true;
                }
                
                // Check for damage system
                if (content.includes('damage') || content.includes('repair')) {
                    hasDamageSystem = true;
                }
                
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Add findings to result
        this.report.gameMechanics.implementedMechanics.vehicles.features = {
            spawning: hasVehicleSpawning,
            saving: hasVehicleSaving,
            customization: hasVehicleCustomization,
            fuel: hasFuelSystem,
            damage: hasDamageSystem
        };
        
        // Add vehicle system assessment
        if (hasVehicleSpawning && hasVehicleSaving && hasVehicleCustomization) {
            this.report.gameMechanics.strengths.push({
                title: "Complete vehicle system",
                description: "The server implements a comprehensive vehicle system with spawning, saving, and customization."
            });
        } else {
            const missingFeatures = [];
            if (!hasVehicleSpawning) missingFeatures.push("vehicle spawning");
            if (!hasVehicleSaving) missingFeatures.push("vehicle persistence");
            if (!hasVehicleCustomization) missingFeatures.push("vehicle customization");
            
            if (missingFeatures.length > 0) {
                this.report.gameMechanics.issues.push({
                    title: "Incomplete vehicle system",
                    description: `The vehicle system is missing key features: ${missingFeatures.join(", ")}.`,
                    solution: "Consider implementing these features to create a more complete vehicle system.",
                    severity: "minor",
                    category: "game-mechanics"
                });
            }
        }
        
        // Check for advanced vehicle features
        if (!hasFuelSystem && !hasDamageSystem) {
            this.report.gameMechanics.issues.push({
                title: "Missing immersive vehicle mechanics",
                description: "Vehicle system lacks immersive mechanics like fuel and damage systems.",
                solution: "Consider adding fuel and damage systems for more realistic vehicle gameplay.",
                severity: "minor",
                category: "game-mechanics"
            });
        }
    }
    
    /**
     * Analyze weapon systems
     */
    async _analyzeWeaponSystems() {
        if (!this.report.gameMechanics.implementedMechanics.weapons.found) return;
        
        const weaponFiles = this.fileList.filter(file => {
            return file.toLowerCase().includes('weapon') || 
                   file.toLowerCase().includes('gun') ||
                   file.toLowerCase().includes('combat');
        });
        
        if (weaponFiles.length === 0) return;
        
        // Check weapon features
        let hasWeaponGiving = false;
        let hasWeaponSaving = false;
        let hasCustomWeapons = false;
        let hasWeaponShops = false;
        let hasAmmoSystem = false;
        
        for (const file of weaponFiles.slice(0, 20)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for weapon giving
                if (content.includes('giveWeapon') || content.includes('addWeapon')) {
                    hasWeaponGiving = true;
                }
                
                // Check for weapon saving
                if ((content.includes('save') || content.includes('database')) && 
                    (content.includes('weapon') || content.includes('gun'))) {
                    hasWeaponSaving = true;
                }
                
                // Check for custom weapons
                if (content.includes('customWeapon') || content.includes('weaponData') || 
                    content.includes('weaponInfo')) {
                    hasCustomWeapons = true;
                }
                
                // Check for weapon shops
                if ((content.includes('shop') || content.includes('store') || content.includes('buy')) && 
                    (content.includes('weapon') || content.includes('gun'))) {
                    hasWeaponShops = true;
                }
                
                // Check for ammo system
                if (content.includes('ammo') || content.includes('ammunition') || 
                    content.includes('bullets')) {
                    hasAmmoSystem = true;
                }
                
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Add findings to result
        this.report.gameMechanics.implementedMechanics.weapons.features = {
            giving: hasWeaponGiving,
            saving: hasWeaponSaving,
            custom: hasCustomWeapons,
            shops: hasWeaponShops,
            ammo: hasAmmoSystem
        };
        
        // Add weapon system assessment
        if (hasWeaponGiving && hasWeaponSaving && hasAmmoSystem) {
            this.report.gameMechanics.strengths.push({
                title: "Complete weapon system",
                description: "The server implements a comprehensive weapon system with giving, saving, and ammunition."
            });
        } else {
            const missingFeatures = [];
            if (!hasWeaponGiving) missingFeatures.push("weapon distribution");
            if (!hasWeaponSaving) missingFeatures.push("weapon persistence");
            if (!hasAmmoSystem) missingFeatures.push("ammunition management");
            
            if (missingFeatures.length > 0) {
                this.report.gameMechanics.issues.push({
                    title: "Incomplete weapon system",
                    description: `The weapon system is missing key features: ${missingFeatures.join(", ")}.`,
                    solution: "Consider implementing these features to create a more complete weapon system.",
                    severity: "minor",
                    category: "game-mechanics"
                });
            }
        }
    }
    
    /**
     * Analyze character systems
     */
    async _analyzeCharacterSystems() {
        if (!this.report.gameMechanics.implementedMechanics.characters.found) return;
        
        const characterFiles = this.fileList.filter(file => {
            return file.toLowerCase().includes('character') || 
                   file.toLowerCase().includes('player') ||
                   file.toLowerCase().includes('customization') ||
                   file.toLowerCase().includes('appearance');
        });
        
        if (characterFiles.length === 0) return;
        
        // Check character features
        let hasCharacterCreation = false;
        let hasCharacterSaving = false;
        let hasAppearanceCustomization = false;
        let hasSkillsSystem = false;
        let hasInventorySystem = false;
        
        for (const file of characterFiles.slice(0, 20)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for character creation
                if (content.includes('createCharacter') || content.includes('newCharacter') || 
                    content.includes('character creation')) {
                    hasCharacterCreation = true;
                }
                
                // Check for character saving
                if ((content.includes('save') || content.includes('database')) && 
                    (content.includes('character') || content.includes('player'))) {
                    hasCharacterSaving = true;
                }
                
                // Check for appearance customization
                if (content.includes('setFaceFeature') || content.includes('setHeadBlend') || 
                    content.includes('setClothes') || content.includes('appearance')) {
                    hasAppearanceCustomization = true;
                }
                
                // Check for skills system
                if (content.includes('skill') || content.includes('stat') || 
                    content.includes('attribute') || content.includes('level')) {
                    hasSkillsSystem = true;
                }
                
                // Check for inventory system
                if (content.includes('inventory') || content.includes('item') || 
                    content.includes('backpack') || content.includes('container')) {
                    hasInventorySystem = true;
                }
                
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Add findings to result
        this.report.gameMechanics.implementedMechanics.characters.features = {
            creation: hasCharacterCreation,
            saving: hasCharacterSaving,
            appearance: hasAppearanceCustomization,
            skills: hasSkillsSystem,
            inventory: hasInventorySystem
        };
        
        // Add character system assessment
        if (hasCharacterCreation && hasCharacterSaving && hasAppearanceCustomization) {
            this.report.gameMechanics.strengths.push({
                title: "Complete character system",
                description: "The server implements a comprehensive character system with creation, saving, and customization."
            });
        } else {
            const missingFeatures = [];
            if (!hasCharacterCreation) missingFeatures.push("character creation");
            if (!hasCharacterSaving) missingFeatures.push("character persistence");
            if (!hasAppearanceCustomization) missingFeatures.push("appearance customization");
            
            if (missingFeatures.length > 0) {
                this.report.gameMechanics.issues.push({
                    title: "Incomplete character system",
                    description: `The character system is missing key features: ${missingFeatures.join(", ")}.`,
                    solution: "Consider implementing these features to create a more complete character system.",
                    severity: "minor",
                    category: "game-mechanics"
                });
            }
        }
        
        // Check for advanced character features
        if (!hasSkillsSystem && !hasInventorySystem) {
            this.report.gameMechanics.issues.push({
                title: "Missing advanced character systems",
                description: "Character system lacks advanced features like skills and inventory management.",
                solution: "Consider adding skills and inventory systems for more depth to character progression.",
                severity: "minor",
                category: "game-mechanics"
            });
        }
    }
    
    /**
     * Analyze Integration
     */
    async analyzeIntegration() {
        console.log('Analyzing integrations and dependencies...');
        
        // Get client-server communication
        await this._analyzeClientServerCommunication();
        
        // Analyze database integration
        await this._analyzeDatabaseIntegration();
        
        console.log(`Integration analysis complete. Found ${this.report.integration.issues.length} issues.`);
    }
    
    /**
     * Analyze client-server communication
     */
    async _analyzeClientServerCommunication() {
        let clientToServerEvents = [];
        let serverToClientEvents = [];
        let eventHandlers = {};
        
        // Analyze client-server event patterns
        for (const file of this.fileList.slice(0, 100)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                const isClientSide = file.includes('/client_packages/');
                const isServerSide = file.includes('/packages/');
                
                if (isClientSide) {
                    // Extract client-to-server events
                    const matches = content.match(/mp\.events\.callRemote\(\s*['"`](\w+)['"`]/g) || [];
                    matches.forEach(match => {
                        const eventMatch = match.match(/['"`](\w+)['"`]/);
                        if (eventMatch && !clientToServerEvents.includes(eventMatch[1])) {
                            clientToServerEvents.push(eventMatch[1]);
                        }
                    });
                }
                
                if (isServerSide) {
                    // Extract server-to-client events
                    const matches = content.match(/mp\.events\.call\(\s*['"`](\w+)['"`]/g) || [];
                    matches.forEach(match => {
                        const eventMatch = match.match(/['"`](\w+)['"`]/);
                        if (eventMatch && !serverToClientEvents.includes(eventMatch[1])) {
                            serverToClientEvents.push(eventMatch[1]);
                        }
                    });
                    
                    // Extract event handlers
                    const handlerMatches = content.match(/mp\.events\.add\(\s*['"`](\w+)['"`]/g) || [];
                    handlerMatches.forEach(match => {
                        const eventMatch = match.match(/['"`](\w+)['"`]/);
                        if (eventMatch) {
                            eventHandlers[eventMatch[1]] = (eventHandlers[eventMatch[1]] || 0) + 1;
                        }
                    });
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Check for event name mismatches (events called but not handled)
        const eventMismatches = [];
        clientToServerEvents.forEach(eventName => {
            if (!eventHandlers[eventName]) {
                eventMismatches.push({
                    event: eventName, 
                    type: 'client-to-server',
                    issue: 'No server-side handler found'
                });
            }
        });
        
        // Add findings to result
        if (clientToServerEvents.length === 0 && serverToClientEvents.length === 0) {
            this.report.integration.issues.push({
                title: "No client-server communication detected",
                description: "No evidence of client-server event communication was found.",
                solution: "Implement proper client-server communication using RAGE MP events.",
                severity: "critical",
                category: "integration"
            });
        } else if (eventMismatches.length > 0) {
            this.report.integration.issues.push({
                title: "Unhandled client-server events",
                description: `Found ${eventMismatches.length} events that may be called but not properly handled.`,
                solution: "Ensure all client-to-server events have proper server-side handlers.",
                severity: "major",
                category: "integration"
            });
        } else {
            this.report.integration.strengths.push({
                title: "Balanced client-server communication",
                description: `Found ${clientToServerEvents.length} client->server events and ${serverToClientEvents.length} server->client events.`
            });
        }
    }
    
    /**
     * Analyze database integration
     */
    async _analyzeDatabaseIntegration() {
        let hasDatabase = false;
        let databaseType = null;
        let connectionMethod = null;
        let tables = [];
        
        // Check for database integration
        for (const file of this.fileList.slice(0, 100)) { // Limit for performance
            try {
                const content = await readFile(file, 'utf8');
                
                // Check for database connection
                if (
                    content.includes('mysql') || 
                    content.includes('mongodb') || 
                    content.includes('mongoose') || 
                    content.includes('sequelize') || 
                    content.includes('sqlite')
                ) {
                    hasDatabase = true;
                    
                    // Determine database type
                    if (content.includes('mysql')) {
                        databaseType = 'MySQL';
                    } else if (content.includes('mongodb') || content.includes('mongoose')) {
                        databaseType = 'MongoDB';
                    } else if (content.includes('sqlite')) {
                        databaseType = 'SQLite';
                    } else if (content.includes('sequelize')) {
                        databaseType = 'SQL (via Sequelize)';
                    }
                    
                    // Identify connection method
                    if (content.includes('createPool')) {
                        connectionMethod = 'connection pooling';
                    } else if (content.includes('connect') || content.includes('createConnection')) {
                        connectionMethod = 'direct connection';
                    }
                    
                    // Attempt to identify table/collection names from SQL queries
                    if (content.includes('SELECT') || content.includes('INSERT INTO') || 
                        content.includes('UPDATE') || content.includes('DELETE FROM')) {
                        
                        const tableMatches = content.match(/(?:FROM|INTO|UPDATE)\s+[`'"]*(\w+)[`'"]*/) || [];
                        tableMatches.forEach(match => {
                            const tableName = match.replace(/(?:FROM|INTO|UPDATE)\s+[`'"]*/g, '').replace(/[`'"]/g, '');
                            if (tableName && !tables.includes(tableName)) {
                                tables.push(tableName);
                            }
                        });
                    }
                }
            } catch (error) {
                // Skip file read errors
            }
        }
        
        // Add findings about database integration
        if (!hasDatabase) {
            // No database integration found
            this.report.integration.issues.push({
                title: "No database integration detected",
                description: "No evidence of database integration was found, which may limit data persistence.",
                solution: "Consider implementing database integration for persistent data storage.",
                severity: "minor",
                category: "integration"
            });
        } else {
            // Add findings about database integration
            this.report.integration.strengths.push({
                title: "Database integration implemented",
                description: `The server uses ${databaseType} with ${connectionMethod || 'unknown connection method'}.`
            });
            
            // Check for tables/collections
            if (tables.length === 0) {
                this.report.integration.issues.push({
                    title: "Unable to identify database tables/collections",
                    description: "Could not identify specific tables or collections used in the database.",
                    solution: "Consider using more explicit table/collection names in queries.",
                    severity: "minor",
                    category: "integration"
                });
            } else if (tables.length >= 5) {
                this.report.integration.strengths.push({
                    title: "Complex database schema",
                    description: `Identified ${tables.length} database tables/collections.`
                });
            }
        }
    }
    
    /**
     * Generate summary of analysis
     */
    generateSummary() {
        // Create a high-level summary from all analysis results
        this.report.summary = {
            totalFiles: this.fileList.length,
            structureScore: this._calculateScore(this.report.structure.issues, 10),
            codeQualityScore: this._calculateScore(this.report.codeQuality.issues, 10),
            performanceScore: this._calculateScore(this.report.performance.issues, 10),
            securityScore: this._calculateScore(this.report.security.issues, 10),
            gameMechanicsScore: this._calculateScore(this.report.gameMechanics.issues, 10),
            integrationScore: this._calculateScore(this.report.integration.issues, 10),
            overallScore: 0,
            criticalIssues: 0,
            majorIssues: 0,
            minorIssues: 0
        };
        
        // Count issues by severity
        const allIssues = [
            ...this.report.structure.issues,
            ...this.report.codeQuality.issues,
            ...this.report.performance.issues,
            ...this.report.security.issues,
            ...this.report.gameMechanics.issues,
            ...this.report.integration.issues
        ];
        
        allIssues.forEach(issue => {
            if (issue.severity === 'critical') this.report.summary.criticalIssues++;
            else if (issue.severity === 'major') this.report.summary.majorIssues++;
            else if (issue.severity === 'minor') this.report.summary.minorIssues++;
        });
        
        // Calculate overall score (weighted average)
        this.report.summary.overallScore = Math.round(
            (
                this.report.summary.structureScore * 1.0 +
                this.report.summary.codeQualityScore * 1.5 +
                this.report.summary.performanceScore * 1.5 +
                this.report.summary.securityScore * 2.0 +
                this.report.summary.gameMechanicsScore * 1.0 +
                this.report.summary.integrationScore * 1.0
            ) / 8
        );
    }
    
    /**
     * Calculate score based on issues
     */
    _calculateScore(issues, baseScore = 10) {
        // Calculate score based on severity of issues
        let deductions = 0;
        
        issues.forEach(issue => {
            if (issue.severity === 'critical') deductions += 1.0;
            else if (issue.severity === 'major') deductions += 0.5;
            else if (issue.severity === 'minor') deductions += 0.2;
        });
        
        return Math.max(0, Math.round((baseScore - deductions) * 10) / 10);
    }
    
    /**
     * Generate prioritized recommendations
     */
    generateRecommendations() {
        // Generate prioritized recommendations based on all issues
        const allIssues = [
            ...this.report.structure.issues,
            ...this.report.codeQuality.issues,
            ...this.report.performance.issues,
            ...this.report.security.issues,
            ...this.report.gameMechanics.issues,
            ...this.report.integration.issues
        ];
        
        // Sort issues by severity
        const sortedIssues = allIssues.sort((a, b) => {
            const severityWeight = {
                'critical': 3,
                'major': 2,
                'minor': 1
            };
            return severityWeight[b.severity] - severityWeight[a.severity];
        });
        
        // Generate recommendations from top issues
        sortedIssues.forEach(issue => {
            this.report.recommendations.push({
                title: issue.title,
                description: issue.description,
                solution: issue.solution,
                priority: issue.severity,
                category: issue.category
            });
        });
    }
    
    /**
     * Generate HTML report
     */
    async generateHtmlReport() {
        console.log('Generating HTML report...');
        
        // Simple HTML template for the report
        const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RAGE MP Server Analysis Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Open Sans", "Helvetica Neue", sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f9f9f9;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #fff;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        h1, h2, h3 {
            color: #2d3748;
            margin-top: 1.5em;
        }
        h1 {
            text-align: center;
            font-size: 2.2em;
            margin-bottom: 1em;
        }
        h2 {
            font-size: 1.8em;
            border-bottom: 2px solid #eaeaea;
            padding-bottom: 0.3em;
        }
        h3 {
            font-size: 1.3em;
            margin-bottom: 0.5em;
        }
        .summary {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 2em;
            background-color: #f8fafc;
            padding: 20px;
            border-radius: 8px;
        }
        .summary-item {
            flex: 1;
            text-align: center;
            padding: 10px;
            min-width: 100px;
        }
        .summary-value {
            font-size: 2em;
            font-weight: bold;
            color: #3182ce;
            display: block;
        }
        .summary-label {
            font-size: 0.9em;
            color: #718096;
        }
        .issues {
            margin-bottom: 2em;
        }
        .issue {
            background-color: #fff;
            border-left: 4px solid #e53e3e;
            margin-bottom: 1em;
            padding: 15px;
            border-radius: 0 4px 4px 0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }
        .issue.major {
            border-left-color: #dd6b20;
        }
        .issue.minor {
            border-left-color: #4299e1;
        }
        .issue-title {
            font-weight: bold;
            margin-bottom: 5px;
            font-size: 1.1em;
        }
        .issue-description {
            margin-bottom: 10px;
        }
        .issue-solution {
            font-style: italic;
            color: #4a5568;
        }
        .issue-meta {
            font-size: 0.8em;
            color: #718096;
            margin-top: 8px;
        }
        .strengths {
            margin-bottom: 2em;
        }
        .strength {
            background-color: #f0fff4;
            border-left: 4px solid #38a169;
            margin-bottom: 1em;
            padding: 15px;
            border-radius: 0 4px 4px 0;
        }
        .strength-title {
            font-weight: bold;
            color: #2f855a;
            margin-bottom: 5px;
        }
        .recommendations {
            background-color: #ebf8ff;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 2em;
        }
        .score-card {
            display: inline-block;
            padding: 10px 20px;
            margin: 10px;
            background-color: #edf2f7;
            border-radius: 8px;
            text-align: center;
        }
        .score-value {
            font-size: 1.8em;
            font-weight: bold;
        }
        .score-card.good {
            background-color: #c6f6d5;
        }
        .score-card.medium {
            background-color: #fefcbf;
        }
        .score-card.poor {
            background-color: #fed7d7;
        }
        .score-label {
            color: #4a5568;
        }
        footer {
            text-align: center;
            margin-top: 2em;
            padding-top: 1em;
            border-top: 1px solid #eaeaea;
            color: #a0aec0;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>RAGE MP Server Analysis Report</h1>
        
        <div class="summary">
            <div class="summary-item">
                <span class="summary-value">${this.report.summary.overallScore}/10</span>
                <span class="summary-label">Overall Score</span>
            </div>
            <div class="summary-item">
                <span class="summary-value">${this.report.summary.totalFiles}</span>
                <span class="summary-label">Files Analyzed</span>
            </div>
            <div class="summary-item">
                <span class="summary-value" style="color: #e53e3e;">${this.report.summary.criticalIssues}</span>
                <span class="summary-label">Critical Issues</span>
            </div>
            <div class="summary-item">
                <span class="summary-value" style="color: #dd6b20;">${this.report.summary.majorIssues}</span>
                <span class="summary-label">Major Issues</span>
            </div>
            <div class="summary-item">
                <span class="summary-value" style="color: #4299e1;">${this.report.summary.minorIssues}</span>
                <span class="summary-label">Minor Issues</span>
            </div>
        </div>
        
        <h2>Category Scores</h2>
        <div>
            <div class="score-card ${this._getScoreClass(this.report.summary.structureScore)}">
                <div class="score-value">${this.report.summary.structureScore}</div>
                <div class="score-label">Structure</div>
            </div>
            <div class="score-card ${this._getScoreClass(this.report.summary.codeQualityScore)}">
                <div class="score-value">${this.report.summary.codeQualityScore}</div>
                <div class="score-label">Code Quality</div>
            </div>
            <div class="score-card ${this._getScoreClass(this.report.summary.performanceScore)}">
                <div class="score-value">${this.report.summary.performanceScore}</div>
                <div class="score-label">Performance</div>
            </div>
            <div class="score-card ${this._getScoreClass(this.report.summary.securityScore)}">
                <div class="score-value">${this.report.summary.securityScore}</div>
                <div class="score-label">Security</div>
            </div>
            <div class="score-card ${this._getScoreClass(this.report.summary.gameMechanicsScore)}">
                <div class="score-value">${this.report.summary.gameMechanicsScore}</div>
                <div class="score-label">Game Mechanics</div>
            </div>
            <div class="score-card ${this._getScoreClass(this.report.summary.integrationScore)}">
                <div class="score-value">${this.report.summary.integrationScore}</div>
                <div class="score-label">Integration</div>
            </div>
        </div>
        
        <h2>Top Recommendations</h2>
        <div class="recommendations">
            ${this._generateHtmlRecommendations()}
        </div>
        
        <h2>Structure Analysis</h2>
        ${this._generateHtmlIssues(this.report.structure.issues)}
        ${this._generateHtmlStrengths(this.report.structure.strengths)}
        
        <h2>Code Quality Analysis</h2>
        ${this._generateHtmlIssues(this.report.codeQuality.issues)}
        ${this._generateHtmlStrengths(this.report.codeQuality.strengths)}
        
        <h2>Performance Analysis</h2>
        ${this._generateHtmlIssues(this.report.performance.issues)}
        ${this._generateHtmlStrengths(this.report.performance.strengths)}
        
        <h2>Security Analysis</h2>
        ${this._generateHtmlIssues(this.report.security.issues)}
        ${this._generateHtmlStrengths(this.report.security.strengths)}
        
        <h2>Game Mechanics Analysis</h2>
        ${this._generateHtmlIssues(this.report.gameMechanics.issues)}
        ${this._generateHtmlStrengths(this.report.gameMechanics.strengths)}
        
        <h2>Integration Analysis</h2>
        ${this._generateHtmlIssues(this.report.integration.issues)}
        ${this._generateHtmlStrengths(this.report.integration.strengths)}
        
        <footer>
            Generated by RAGE MP Server Code Analyzer on ${new Date().toLocaleDateString()}
        </footer>
    </div>
</body>
</html>`;
        
        return html;
    }
    
    /**
     * Helper to generate HTML for issues
     */
    _generateHtmlIssues(issues) {
        if (!issues || issues.length === 0) {
            return '<p>No issues detected in this category.</p>';
        }
        
        return `
        <div class="issues">
            ${issues.map(issue => `
                <div class="issue ${issue.severity}">
                    <div class="issue-title">${issue.title}</div>
                    <div class="issue-description">${issue.description}</div>
                    <div class="issue-solution"><strong>Solution:</strong> ${issue.solution}</div>
                    <div class="issue-meta">Severity: ${issue.severity} | Category: ${issue.category}</div>
                </div>
            `).join('')}
        </div>`;
    }
    
    /**
     * Helper to generate HTML for strengths
     */
    _generateHtmlStrengths(strengths) {
        if (!strengths || strengths.length === 0) {
            return '';
        }
        
        return `
        <h3>Strengths</h3>
        <div class="strengths">
            ${strengths.map(strength => `
                <div class="strength">
                    <div class="strength-title">${strength.title}</div>
                    <div>${strength.description}</div>
                </div>
            `).join('')}
        </div>`;
    }
    
    /**
     * Helper to generate HTML for recommendations
     */
    _generateHtmlRecommendations() {
        // Get top 5 critical/major recommendations
        const topRecs = this.report.recommendations
            .filter(rec => rec.priority === 'critical' || rec.priority === 'major')
            .slice(0, 5);
            
        if (topRecs.length === 0) {
            return '<p>No critical or major recommendations to display.</p>';
        }
        
        return topRecs.map(rec => `
            <div class="issue ${rec.priority}">
                <div class="issue-title">${rec.title}</div>
                <div class="issue-description">${rec.description}</div>
                <div class="issue-solution"><strong>Solution:</strong> ${rec.solution}</div>
                <div class="issue-meta">Priority: ${rec.priority} | Category: ${rec.category}</div>
            </div>
        `).join('');
    }
    
    /**
     * Helper to get score class based on value
     */
    _getScoreClass(score) {
        if (score >= 8) return 'good';
        if (score >= 6) return 'medium';
        return 'poor';
    }
    
    /**
     * Generate Markdown report
     */
    async generateMarkdownReport() {
        console.log('Generating Markdown report...');
        
        // Markdown template for the report
        const markdown = `# RAGE MP Server Analysis Report

## Summary

**Overall Score: ${this.report.summary.overallScore}/10**

- **Files Analyzed:** ${this.report.summary.totalFiles}
- **Critical Issues:** ${this.report.summary.criticalIssues}
- **Major Issues:** ${this.report.summary.majorIssues}
- **Minor Issues:** ${this.report.summary.minorIssues}

### Category Scores

| Category | Score |
|----------|-------|
| Structure | ${this.report.summary.structureScore}/10 |
| Code Quality | ${this.report.summary.codeQualityScore}/10 |
| Performance | ${this.report.summary.performanceScore}/10 |
| Security | ${this.report.summary.securityScore}/10 |
| Game Mechanics | ${this.report.summary.gameMechanicsScore}/10 |
| Integration | ${this.report.summary.integrationScore}/10 |

## Top Recommendations

${this._generateMarkdownRecommendations()}

## Structure Analysis

${this._generateMarkdownIssues(this.report.structure.issues)}
${this._generateMarkdownStrengths(this.report.structure.strengths)}

## Code Quality Analysis

${this._generateMarkdownIssues(this.report.codeQuality.issues)}
${this._generateMarkdownStrengths(this.report.codeQuality.strengths)}

## Performance Analysis

${this._generateMarkdownIssues(this.report.performance.issues)}
${this._generateMarkdownStrengths(this.report.performance.strengths)}

## Security Analysis

${this._generateMarkdownIssues(this.report.security.issues)}
${this._generateMarkdownStrengths(this.report.security.strengths)}

## Game Mechanics Analysis

${this._generateMarkdownIssues(this.report.gameMechanics.issues)}
${this._generateMarkdownStrengths(this.report.gameMechanics.strengths)}

## Integration Analysis

${this._generateMarkdownIssues(this.report.integration.issues)}
${this._generateMarkdownStrengths(this.report.integration.strengths)}

---
Generated by RAGE MP Server Code Analyzer on ${new Date().toLocaleDateString()}`;
        
        return markdown;
    }
    
    /**
     * Helper to generate Markdown for issues
     */
    _generateMarkdownIssues(issues) {
        if (!issues || issues.length === 0) {
            return 'No issues detected in this category.\n';
        }
        
        return `### Issues

${issues.map(issue => `
#### ${issue.title} (${issue.severity})

**Description:** ${issue.description}

**Solution:** ${issue.solution}

**Category:** ${issue.category}
`).join('\n')}`;
    }
    
    /**
     * Helper to generate Markdown for strengths
     */
    _generateMarkdownStrengths(strengths) {
        if (!strengths || strengths.length === 0) {
            return '';
        }
        
        return `### Strengths

${strengths.map(strength => `
- **${strength.title}:** ${strength.description}
`).join('\n')}`;
    }
    
    /**
     * Helper to generate Markdown for recommendations
     */
    _generateMarkdownRecommendations() {
        // Get top 5 critical/major recommendations
        const topRecs = this.report.recommendations
            .filter(rec => rec.priority === 'critical' || rec.priority === 'major')
            .slice(0, 5);
            
        if (topRecs.length === 0) {
            return 'No critical or major recommendations to display.\n';
        }
        
        return topRecs.map(rec => `
### ${rec.title} (${rec.priority})

**Description:** ${rec.description}

**Solution:** ${rec.solution}

**Category:** ${rec.category}
`).join('\n');
    }
    
    /**
     * Save report to file
     */
    async saveReport(outputPath, format = 'html') {
        let reportContent;
        let filename;
        
        if (format === 'html') {
            reportContent = await this.generateHtmlReport();
            filename = 'rage-mp-analysis-report.html';
        } else if (format === 'markdown' || format === 'md') {
            reportContent = await this.generateMarkdownReport();
            filename = 'rage-mp-analysis-report.md';
        } else {
            throw new Error(`Unsupported report format: ${format}`);
        }
        
        // Create output directory if it doesn't exist
        if (!fs.existsSync(outputPath)) {
            await mkdir(outputPath, { recursive: true });
        }
        
        const outputFilePath = path.join(outputPath, filename);
        await writeFile(outputFilePath, reportContent);
        console.log(`Report saved to: ${outputFilePath}`);
        
        return outputFilePath;
    }
}

/**
 * Main function to run analysis
 */
async function main() {
    try {
        // Get repo path from command line arguments
        const repoPath = process.argv[2];
        
        if (!repoPath) {
            console.error('Please provide a repository path as a command-line argument.');
            console.log('Usage: node rage-mp-analyzer.js <path-to-your-repo>');
            return;
        }
        
        console.log(`Starting analysis of repository: ${repoPath}`);
        console.log('This may take several minutes depending on the size of the codebase...');
        
        // Create output directory
        const outputDir = path.join('.', 'reports');
        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }
        
        // Run analysis
        const analyzer = new RageMP_Analyzer(repoPath);
        const report = await analyzer.analyze();
        
        // Generate reports
        const htmlReportPath = await analyzer.saveReport(outputDir, 'html');
        const mdReportPath = await analyzer.saveReport(outputDir, 'markdown');
        
        // Print summary
        console.log('\nAnalysis complete!');
        console.log(`HTML report saved to: ${htmlReportPath}`);
        console.log(`Markdown report saved to: ${mdReportPath}`);
        console.log('\nSummary:');
        console.log(`Overall Score: ${report.summary.overallScore}/10`);
        console.log(`Critical Issues: ${report.summary.criticalIssues}`);
        console.log(`Major Issues: ${report.summary.majorIssues}`);
        console.log(`Minor Issues: ${report.summary.minorIssues}`);
        
        console.log('\nCategory Scores:');
        console.log(`Structure: ${report.summary.structureScore}/10`);
        console.log(`Code Quality: ${report.summary.codeQualityScore}/10`);
        console.log(`Performance: ${report.summary.performanceScore}/10`);
        console.log(`Security: ${report.summary.securityScore}/10`);
        console.log(`Game Mechanics: ${report.summary.gameMechanicsScore}/10`);
        console.log(`Integration: ${report.summary.integrationScore}/10`);
        
    } catch (error) {
        console.error('Error running analysis:', error);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = RageMP_Analyzer;
