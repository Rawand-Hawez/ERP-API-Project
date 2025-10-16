// ERP API - Unified Service using Bun and Express
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

// Configuration
const PORT = Number(process.env.PORT || 3080);
const NODE_ENV = process.env.NODE_ENV || 'development';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];

// Dynamics 365 Configuration
const DYNAMICS_CONFIG = {
  TENANT_ID: process.env.TENANT_ID || '',
  CLIENT_ID: process.env.CLIENT_ID || '',
  CLIENT_SECRET: process.env.CLIENT_SECRET || '',
  DYNAMICS_BASE_URL: process.env.DYNAMICS_BASE_URL || 'https://krd-prod.operations.eu.dynamics.com'
};

// Initialize Express app
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// CORS configuration
const corsOptions: cors.CorsOptions = {
  origin: (origin: string | undefined, callback: (error: Error | null, allow?: boolean) => void) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));

// Rate limiting
const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 auth attempts per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalRateLimit);
app.use(express.json({ limit: '10mb' }));

// Types
interface AuthenticatedRequest extends Request {
  user?: {
    userId: string;
    username: string;
    role: string;
    subsidiaries?: string[];
  };
}

interface User {
  username: string;
  password: string;
  role: string;
  subsidiaries: string[];
}

// Mock users (in production, use proper database)
const users: User[] = [
  { username: 'admin', password: 'admin123', role: 'admin', subsidiaries: ['*'] },
  { username: 'finance', password: 'finance123', role: 'finance', subsidiaries: ['KRD', 'KRDSUB1'] },
  { username: 'readonly', password: 'readonly123', role: 'readonly', subsidiaries: ['KRD'] },
];

// Mock subsidiaries data
const subsidiaries = [
  {
    LegalEntityId: 'KH01',
    Name: 'KRD Holding Main',
    PrimaryContactPhone: '+964-750-123-4567',
    AddressCity: 'Erbil',
    AddressCountryRegionISOCode: 'IQ',
    UseForFinancialConsolidationProcess: 'Yes',
  },
  {
    LegalEntityId: 'KH02',
    Name: 'KRD Holding Branch',
    PrimaryContactPhone: '+964-750-987-6543',
    AddressCity: 'Sulaymaniyah',
    AddressCountryRegionISOCode: 'IQ',
    UseForFinancialConsolidationProcess: 'Yes',
  },
];

// Mock operating units data
const operatingUnits = [
  { code: '100', name: 'Executive Management', type: 'cost_center' },
  { code: '110', name: 'Finance Department', type: 'cost_center' },
  { code: '140', name: 'Human Resources', type: 'cost_center' },
  { code: '150', name: 'IT Department', type: 'cost_center' },
  { code: '160', name: 'Operations', type: 'cost_center' },
  { code: '170', name: 'Marketing', type: 'cost_center' },
  { code: '180', name: 'Sales Department', type: 'cost_center' },
  { code: '190', name: 'Customer Service', type: 'cost_center' },
  { code: '200', name: 'Business Development', type: 'cost_center' },
  { code: 'PC001', name: 'Profit Center 1', type: 'profit_center' },
  { code: 'PC002', name: 'Profit Center 2', type: 'profit_center' },
];
// Financial data processing function
function processFinancialData(
  accountEntries: any[],
  journalEntries: any[],
  subsidiary: string,
  year: number,
  month: number,
  profitCenterFilter?: string,
  customExchangeRate: number = 1400
) {
  // Transform account entries
  const transformedEntries = accountEntries.map((accountEntry: any) => {
    const journalEntry = journalEntries.find((je: any) => je.SourceKey === accountEntry.GeneralJournalEntry);

    // Parse ledger dimensions
    const dimensions = parseLedgerDimensions(accountEntry.LedgerDimensionValuesJson || '[]');
    const mainAccount = dimensions.mainAccount || accountEntry.LedgerAccount.replace(/---$/, '');

    // Get the actual transaction currency from Dynamics 365
    const transactionCurrency = accountEntry.TransactionCurrencyCode || 'IQD';
    const transactionAmount = accountEntry.TransactionCurrencyAmount || 0;
    const accountingAmount = accountEntry.AccountingCurrencyAmount || transactionAmount;

    // Determine amounts in both currencies
    let amountIQD: number;
    let amountUSD: number;

    if (transactionCurrency === 'USD') {
      // Transaction is in USD, convert to IQD
      amountUSD = transactionAmount;
      amountIQD = Math.round(transactionAmount * customExchangeRate * 100) / 100;
    } else {
      // Transaction is in IQD (or use accounting currency amount)
      amountIQD = transactionCurrency === 'IQD' ? transactionAmount : accountingAmount;
      amountUSD = Math.round((amountIQD / customExchangeRate) * 100) / 100;
    }

    const isDebit = accountEntry.IsCredit === 'No';
    const accountType = classifyAccountType(mainAccount);

    return {
      accountNumber: mainAccount,
      accountName: getAccountName(mainAccount, accountType),
      debit: isDebit ? transactionAmount : 0,
      credit: !isDebit ? transactionAmount : 0,
      balance: transactionAmount * (isDebit ? 1 : -1),
      date: journalEntry?.AccountingDate || new Date().toISOString().split('T')[0],
      description: accountEntry.Text || '',
      currency: transactionCurrency,
      debitIQD: isDebit ? amountIQD : 0,
      creditIQD: !isDebit ? amountIQD : 0,
      debitUSD: isDebit ? amountUSD : 0,
      creditUSD: !isDebit ? amountUSD : 0,
      costCenter: dimensions.costCenter,
      profitCenter: dimensions.profitCenter,
      accountType,
    };
  });

  // Filter by profit center if specified
  let filteredEntries = transformedEntries;
  if (profitCenterFilter) {
    filteredEntries = transformedEntries.filter(entry =>
      entry.profitCenter === profitCenterFilter
    );
  }

  // Separate revenue and cost entries
  const revenueEntries = filteredEntries.filter(entry => entry.accountType === 'revenue');
  const costEntries = filteredEntries.filter(entry => entry.accountType === 'cost');

  // Calculate totals
  const totalRevenue = revenueEntries.reduce((sum: number, entry: any) => sum + entry.creditIQD, 0);
  const totalCosts = costEntries.reduce((sum: number, entry: any) => sum + entry.debitIQD, 0);
  const netProfit = totalRevenue - totalCosts;

  // Calculate USD amounts
  const totalRevenueUSD = Math.round((totalRevenue / customExchangeRate) * 100) / 100;
  const totalCostsUSD = Math.round((totalCosts / customExchangeRate) * 100) / 100;
  const netProfitUSD = Math.round((netProfit / customExchangeRate) * 100) / 100;

  // Create revenue details
  const revenueDetails = revenueEntries.map(entry => ({
    accountNumber: entry.accountNumber,
    accountName: entry.accountName,
    amount: Math.abs(entry.credit),
    amountIQD: Math.abs(entry.creditIQD),
    amountUSD: Math.abs(entry.creditUSD),
    description: entry.description,
    currency: entry.currency,
  }));

  // Create cost line items
  const costLineItems = costEntries.map(entry => ({
    accountNumber: entry.accountNumber,
    accountName: entry.accountName,
    amount: entry.debit,
    amountIQD: entry.debitIQD,
    amountUSD: entry.debitUSD,
    description: entry.description,
    costCenter: entry.costCenter,
    profitCenter: entry.profitCenter,
    currency: entry.currency,
  }));

  // Calculate currency breakdown
  const currencyBreakdown = {
    IQD: {
      count: transformedEntries.filter(e => e.currency === 'IQD').length,
      totalDebit: transformedEntries.filter(e => e.currency === 'IQD').reduce((sum, e) => sum + e.debitIQD, 0),
      totalCredit: transformedEntries.filter(e => e.currency === 'IQD').reduce((sum, e) => sum + e.creditIQD, 0),
    },
    USD: {
      count: transformedEntries.filter(e => e.currency === 'USD').length,
      totalDebit: transformedEntries.filter(e => e.currency === 'USD').reduce((sum, e) => sum + e.debit, 0),
      totalCredit: transformedEntries.filter(e => e.currency === 'USD').reduce((sum, e) => sum + e.credit, 0),
    },
  };

  return {
    subsidiary,
    year,
    month,
    totalRevenue: Math.abs(totalRevenue),
    totalCosts,
    netProfit,
    totalRevenueUSD,
    totalCostsUSD,
    netProfitUSD,
    exchangeRate: customExchangeRate,
    baseCurrency: 'IQD',
    currencyBreakdown,
    revenueDetails,
    costLineItems,
    entryCount: transformedEntries.length,
    generatedAt: new Date().toISOString(),
  };
}

// Helper functions for financial data processing
function parseLedgerDimensions(dimensionJson: string): { mainAccount?: string; costCenter?: string; profitCenter?: string } {
  try {
    const dimensions = JSON.parse(dimensionJson || '[]');
    let mainAccount: string | undefined;
    let costCenter: string | undefined;
    let profitCenter: string | undefined;

    const costCenterCodes = ['100', '110', '140', '141', '145', '150', '160', '170', '180', '190', '200', '999'];

    for (const dimension of dimensions) {
      for (const [key, value] of Object.entries(dimension)) {
        if (key === 'MAINACCOUNT') {
          mainAccount = value as string;
        } else if (costCenterCodes.includes(value as string)) {
          costCenter = value as string;
        } else {
          profitCenter = value as string;
        }
      }
    }

    return { mainAccount, costCenter, profitCenter };
  } catch (error) {
    console.error('Error parsing ledger dimensions:', error);
    return {};
  }
}

function classifyAccountType(accountNumber: string): 'revenue' | 'cost' | 'other' {
  // Revenue accounts (5000* series)
  if (accountNumber.startsWith('5000') || accountNumber.startsWith('5001') || 
      accountNumber.startsWith('5002') || accountNumber.startsWith('5003') ||
      accountNumber.startsWith('5004') || accountNumber.startsWith('5005') ||
      accountNumber.startsWith('5006') || accountNumber.startsWith('5007') ||
      accountNumber.startsWith('5008') || accountNumber.startsWith('5009') ||
      accountNumber.startsWith('50010') || accountNumber.startsWith('50011') ||
      accountNumber.startsWith('5100') || accountNumber.startsWith('5200') ||
      accountNumber.startsWith('5300')) {
    return 'revenue';
  }

  // Cost accounts (6000* and 7000* series)
  if (accountNumber.startsWith('6000') || accountNumber.startsWith('6100') ||
      accountNumber.startsWith('6200') || accountNumber.startsWith('6300') ||
      accountNumber.startsWith('6900') || accountNumber.startsWith('7000') ||
      accountNumber.startsWith('7002') || accountNumber.startsWith('7003') ||
      accountNumber.startsWith('7010') || accountNumber.startsWith('7011') ||
      accountNumber.startsWith('7012') || accountNumber.startsWith('7013') ||
      accountNumber.startsWith('7014') || accountNumber.startsWith('7015') ||
      accountNumber.startsWith('7016') || accountNumber.startsWith('7017') ||
      accountNumber.startsWith('7018') || accountNumber.startsWith('7100') ||
      accountNumber.startsWith('7102') || accountNumber.startsWith('7103') ||
      accountNumber.startsWith('7104') || accountNumber.startsWith('7110') ||
      accountNumber.startsWith('7111') || accountNumber.startsWith('7112') ||
      accountNumber.startsWith('7114') || accountNumber.startsWith('7115') ||
      accountNumber.startsWith('7116') || accountNumber.startsWith('7117') ||
      accountNumber.startsWith('7118') || accountNumber.startsWith('7119') ||
      accountNumber.startsWith('7120') || accountNumber.startsWith('7121') ||
      accountNumber.startsWith('7130') || accountNumber.startsWith('7140') ||
      accountNumber.startsWith('7150') || accountNumber.startsWith('7160') ||
      accountNumber.startsWith('7200') || accountNumber.startsWith('7201') ||
      accountNumber.startsWith('7202') || accountNumber.startsWith('7203') ||
      accountNumber.startsWith('7204') || accountNumber.startsWith('7210') ||
      accountNumber.startsWith('7220') || accountNumber.startsWith('7221') ||
      accountNumber.startsWith('7222') || accountNumber.startsWith('7225') ||
      accountNumber.startsWith('7230') || accountNumber.startsWith('7232') ||
      accountNumber.startsWith('7235') || accountNumber.startsWith('7240') ||
      accountNumber.startsWith('7242') || accountNumber.startsWith('7244') ||
      accountNumber.startsWith('7250') || accountNumber.startsWith('7260') ||
      accountNumber.startsWith('7263') || accountNumber.startsWith('7264') ||
      accountNumber.startsWith('7265') || accountNumber.startsWith('7266') ||
      accountNumber.startsWith('7267') || accountNumber.startsWith('7268') ||
      accountNumber.startsWith('7273') || accountNumber.startsWith('7287') ||
      accountNumber.startsWith('7300') || accountNumber.startsWith('7400') ||
      accountNumber.startsWith('7460') || accountNumber.startsWith('7470')) {
    return 'cost';
  }

  // Special cash account handling
  if (accountNumber.startsWith('100004')) return 'revenue'; // Customer payments
  if (accountNumber.startsWith('100003')) return 'cost'; // Petty cash expenses

  return 'other';
}

function getAccountName(accountNumber: string, accountType: string): string {
  // You can expand this with actual account names from your chart of accounts
  const accountNames: Record<string, string> = {
    '50001': 'Service Revenue',
    '50002': 'Product Sales',
    '50003': 'Consulting Revenue',
    '50004': 'Sales Discount',
    '50005': 'Purchase Revenue',
    '50006': 'Product Revenue',
    '50007': 'Sales Return',
    '50008': 'E-Commerce Revenue',
    '50009': 'Subscription Revenue',
    '50010': 'Telecom Revenue',
    '50011': 'Other Sales Revenue',
    '6000': 'Cost of Goods Sold',
    '6100': 'Project Expenses',
    '6200': 'Rental Expense',
    '6300': 'Subcontractor Cost',
    '6900': 'Project Salaries',
    '7000': 'Direct Salary',
    '7002': 'Overtime',
    '7003': 'Medical Allowance',
    '7010': 'Housing Allowance',
    '7011': 'Transportation Allowance',
    '7012': 'Education Allowance',
    '7013': 'Annual Leave Tickets',
    '7014': 'Bonus',
    '7015': 'End of Service',
    '7016': 'Consultant/Contractor Fees',
    '7017': 'Residency/Visa-Employees',
    '7018': 'Vehicle Rental',
    '7100': 'Office Rent',
    '7102': 'Utilities',
    '7103': 'Office Repair Maintenance',
    '7104': 'Business Development',
    '7110': 'Depreciation - Furniture',
    '7111': 'Depreciation - Computers',
    '7112': 'Depreciation - Equipment',
    '7114': 'Depreciation - Cars',
    '7115': 'Depreciation - Other Fixed Assets',
  };

  return accountNames[accountNumber] || 
         (accountType === 'revenue' ? 'Revenue Account' : 
          accountType === 'cost' ? 'Expense Account' : 'Other Account');
}


// JWT Authentication middleware
const authenticateToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    res.status(401).json({ error: 'Access token required' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = {
      userId: decoded.userId,
      username: decoded.username,
      role: decoded.role,
      subsidiaries: decoded.subsidiaries,
    };
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
    return;
  }
};

// Role-based authorization middleware
const authorizeRoles = (...allowedRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: 'Insufficient permissions',
        required: allowedRoles,
        current: req.user.role
      });
      return;
    }
    next();
  };
};

// Subsidiary access authorization middleware
const authorizeSubsidiaryAccess = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  // Admin users have access to all subsidiaries
  if (req.user.role === 'admin') {
    next();
    return;
  }

  const requestedSubsidiary = (req as any).params.subsidiary;
  if (!requestedSubsidiary) {
    res.status(400).json({ error: 'Subsidiary parameter required' });
    return;
  }

  // Check if user has access to the requested subsidiary
  if (req.user.subsidiaries && !req.user.subsidiaries.includes(requestedSubsidiary)) {
    res.status(403).json({
      error: 'Access denied to this subsidiary',
      subsidiary: requestedSubsidiary,
      userSubsidiaries: req.user.subsidiaries
    });
    return;
  }

  next();
};

// Dynamics 365 OAuth Token Management
let tokenCache: {
  token: string | null;
  expiry: Date | null;
} = {
  token: null,
  expiry: null,
};

async function getDynamicsAccessToken(): Promise<any> {
  // Check cache
  if (tokenCache.token && tokenCache.expiry && new Date() < tokenCache.expiry) {
    return {
      token_type: 'Bearer',
      expires_in: 3600,
      ext_expires_in: 3600,
      access_token: tokenCache.token,
    };
  }

  try {
    const tokenUrl = `https://login.microsoftonline.com/${DYNAMICS_CONFIG.TENANT_ID}/oauth2/v2.0/token`;
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: DYNAMICS_CONFIG.CLIENT_ID,
      client_secret: DYNAMICS_CONFIG.CLIENT_SECRET,
      scope: `${DYNAMICS_CONFIG.DYNAMICS_BASE_URL}/.default`,
    });

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    });

    if (!response.ok) {
      throw new Error(`Failed to get access token: ${response.statusText}`);
    }

    const data = await response.json();

    // Cache token with 5-minute safety margin
    tokenCache.token = data.access_token;
    tokenCache.expiry = new Date(Date.now() + (data.expires_in - 300) * 1000);

    return data;
  } catch (error) {
    console.error('Error getting Dynamics 365 access token:', error);
    throw error;
  }
}

// Routes

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'erp-api',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    version: '2.0.0',
    runtime: 'bun',
  });
});

/**
 * Test endpoint
 */
app.get('/test', (req, res) => {
  res.json({
    message: 'ERP API is running with Bun!',
    timestamp: new Date().toISOString(),
    environment: NODE_ENV,
    port: PORT,
    runtime: 'bun',
    node_version: process.version,
    memory_usage: process.memoryUsage(),
  });
});

/**
 * Root endpoint
 */
app.get('/', (req, res) => {
  res.json({
    message: 'ERP API - Powered by Bun',
    version: '2.0.0',
    runtime: 'bun',
    security: 'All API endpoints require JWT authentication',
    endpoints: {
      'GET /health': 'Health check (public)',
      'GET /test': 'Test endpoint (public)',
      'POST /api/auth/login': 'User login (public)',
      'GET /api/token': 'Get Dynamics 365 access token (authenticated)',
      'GET /api/subsidiaries': 'Get all subsidiaries (admin/finance)',
      'GET /api/financial/:subsidiary/:year/:month': 'Get financial data (authenticated)',
    },
    default_users: {
      admin: { username: 'admin', password: 'admin123', role: 'admin' },
      finance: { username: 'finance', password: 'finance123', role: 'finance' },
      readonly: { username: 'readonly', password: 'readonly123', role: 'readonly' },
    },
    timestamp: new Date().toISOString(),
  });
});

/**
 * User login endpoint
 */
app.post('/api/auth/login', authRateLimit, async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    const user = users.find(u => u.username === username && u.password === password);

    if (!user) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        userId: user.username,
        username: user.username,
        role: user.role,
        subsidiaries: user.subsidiaries,
      },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      user: {
        username: user.username,
        role: user.role,
        subsidiaries: user.subsidiaries,
      },
    });
  } catch (error: any) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * Get Dynamics 365 access token
 */
app.get('/api/token',
  authenticateToken,
  authorizeRoles('admin', 'finance'),
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const tokenData = await getDynamicsAccessToken();
      res.json(tokenData);
    } catch (error: any) {
      console.error('Token error:', error);
      res.status(500).json({ error: 'Failed to get Dynamics 365 access token' });
    }
  }
);

/**
 * Get all subsidiaries
 */
app.get('/api/subsidiaries',
  authenticateToken,
  authorizeRoles('admin', 'finance'),
  (req: AuthenticatedRequest, res: Response) => {
    try {
      res.json({
        subsidiaries,
        count: subsidiaries.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error('Error fetching subsidiaries:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get subsidiary by code
 */
app.get('/api/subsidiaries/:code',
  authenticateToken,
  authorizeRoles('admin', 'finance'),
  (req: AuthenticatedRequest, res: Response) => {
    try {
      const { code } = req.params;
      const subsidiary = subsidiaries.find((sub) => sub.LegalEntityId === code);

      if (!subsidiary) {
        return res.status(404).json({ error: 'Subsidiary not found' });
      }

      res.json(subsidiary);
    } catch (error: any) {
      console.error('Error fetching subsidiary:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get operating units
 */
app.get('/api/operating-units',
  authenticateToken,
  authorizeRoles('admin', 'finance'),
  (req: AuthenticatedRequest, res: Response) => {
    try {
      res.json({
        operatingUnits,
        count: operatingUnits.length,
        timestamp: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error('Error fetching operating units:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get operating units by type
 */
app.get('/api/operating-units/:type',
  authenticateToken,
  authorizeRoles('admin', 'finance'),
  (req: AuthenticatedRequest, res: Response) => {
    try {
      const { type } = req.params;

      if (type !== 'cost_center' && type !== 'profit_center') {
        return res.status(400).json({ error: 'Invalid type. Must be cost_center or profit_center' });
      }

      const filteredUnits = operatingUnits.filter((unit) => unit.type === type);

      res.json({
        operatingUnits: filteredUnits,
        count: filteredUnits.length,
        type,
        timestamp: new Date().toISOString(),
      });
    } catch (error: any) {
      console.error('Error fetching operating units by type:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get financial data (mock implementation)
 */
app.get('/api/financial/:subsidiary/:year/:month',
  authenticateToken,
  authorizeSubsidiaryAccess,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { subsidiary, year, month } = req.params;
      const { profitCenter, exchangeRate } = req.query;

      // Validate parameters
      const yearNum = parseInt(year);
      const monthNum = parseInt(month);

      if (isNaN(yearNum) || isNaN(monthNum) || monthNum < 1 || monthNum > 12) {
        return res.status(400).json({ error: 'Invalid year or month' });
      }

      // Get real Dynamics 365 financial data
      try {
        // Get access token
        const tokenData = await getDynamicsAccessToken();
        const accessToken = tokenData.access_token;

        // Calculate date range for the month
        const startDate = new Date(yearNum, monthNum - 1, 1);
        const endDate = new Date(yearNum, monthNum, 1);
        const startDateStr = startDate.toISOString().split('T')[0];
        const endDateStr = endDate.toISOString().split('T')[0];

        // Fetch journal entries from Dynamics 365
        const journalUrl = `${DYNAMICS_CONFIG.DYNAMICS_BASE_URL}/data/GeneralJournalEntryBiEntities?$filter=SubledgerVoucherDataAreaId eq '${subsidiary}' and AccountingDate ge ${startDateStr} and AccountingDate lt ${endDateStr}&$select=SourceKey,JournalNumber,AccountingDate,SubledgerVoucherDataAreaId`;
        
        const journalResponse = await fetch(journalUrl, {
          headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
          },
        });

        if (!journalResponse.ok) {
          throw new Error(`Dynamics 365 API error: ${journalResponse.statusText}`);
        }

        const journalData = await journalResponse.json() as { value: any[] };
        const journalEntries = journalData.value || [];

        if (journalEntries.length === 0) {
          return res.json({
            subsidiary,
            year: yearNum,
            month: monthNum,
            totalRevenue: 0,
            totalCosts: 0,
            totalRevenueUSD: 0,
            totalCostsUSD: 0,
            netProfit: 0,
            netProfitUSD: 0,
            exchangeRate: exchangeRate ? parseFloat(exchangeRate as string) : 1400,
            baseCurrency: 'IQD',
            revenueDetails: [],
            costLineItems: [],
            entryCount: 0,
            generatedAt: new Date().toISOString(),
          });
        }

        // Fetch account entries for all journal entries
        const journalEntryKeys = journalEntries.map((entry: any) => entry.SourceKey);
        const batchSize = 10;
        const allAccountEntries: any[] = [];

        for (let i = 0; i < journalEntryKeys.length; i += batchSize) {
          const batch = journalEntryKeys.slice(i, i + batchSize);
          const filterConditions = batch.map(key => `GeneralJournalEntry eq ${key}`).join(' or ');

          const accountUrl = `${DYNAMICS_CONFIG.DYNAMICS_BASE_URL}/data/GeneralJournalAccountEntryBiEntities?$filter=${filterConditions}&$select=GeneralJournalEntry,LedgerAccount,IsCredit,TransactionCurrencyAmount,TransactionCurrencyCode,AccountingCurrencyAmount,Text,LedgerDimensionValuesJson`;

          const accountResponse = await fetch(accountUrl, {
            headers: {
              'Authorization': `Bearer ${accessToken}`,
              'Content-Type': 'application/json',
            },
          });

          if (accountResponse.ok) {
            const accountData = await accountResponse.json() as { value: any[] };
            allAccountEntries.push(...(accountData.value || []));
          }
        }

        // Process and aggregate the data
        const rate = exchangeRate ? parseFloat(exchangeRate as string) : 1400;
        const aggregatedData = processFinancialData(allAccountEntries, journalEntries, subsidiary, yearNum, monthNum, profitCenter as string, rate);

        res.json(aggregatedData);
      } catch (error: any) {
        console.error('Error fetching Dynamics 365 data:', error);
        res.status(500).json({ error: 'Failed to fetch financial data from Dynamics 365' });
      }
    } catch (error: any) {
      console.error('Error fetching financial data:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

/**
 * Get P&L data
 */
app.get('/api/financial/:subsidiary/:year/:month/pl',
  authenticateToken,
  authorizeSubsidiaryAccess,
  async (req: AuthenticatedRequest, res: Response) => {
    try {
      const { subsidiary, year, month } = req.params;
      const { profitCenter, exchangeRate } = req.query;

      // For now, return the same as financial data but P&L focused
      const mockPLData = {
        subsidiary,
        year: parseInt(year),
        month: parseInt(month),
        totalRevenue: Math.floor(Math.random() * 1000000) + 500000,
        totalCosts: Math.floor(Math.random() * 800000) + 300000,
        netProfit: 0,
        revenueDetails: [
          {
            accountNumber: '50001',
            accountName: 'Service Revenue',
            amount: 500000,
            description: 'Consulting services',
            currency: 'IQD',
          },
        ],
        costLineItems: [
          {
            accountNumber: '7000',
            accountName: 'Direct Salary',
            amount: 200000,
            description: 'Employee salaries',
            costCenter: '110',
            profitCenter: profitCenter as string || 'PC001',
            currency: 'IQD',
          },
        ],
        entryCount: 25,
        generatedAt: new Date().toISOString(),
      };

      mockPLData.netProfit = mockPLData.totalRevenue - mockPLData.totalCosts;

      res.json(mockPLData);
    } catch (error: any) {
      console.error('Error fetching P&L data:', error);
      res.status(500).json({ error: error.message });
    }
  }
);

// Error handling middleware
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const HOST = NODE_ENV === 'production' ? '0.0.0.0' : 'localhost';

console.log(`\n🚀 Starting ERP API with Bun...`);
console.log(`✓ Environment: ${NODE_ENV}`);
console.log(`✓ Port: ${PORT}`);
console.log(`✓ Host: ${HOST}`);

app.listen(PORT, HOST, () => {
  console.log(`\n🚀 ERP API running on http://${HOST}:${PORT}`);
  console.log(`✓ Runtime: Bun`);
  console.log(`✓ Node Version: ${process.version}`);
  console.log(`✓ Working Directory: ${process.cwd()}`);
  console.log(`✓ CORS Origins: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(`✓ JWT Secret configured: ${!!JWT_SECRET}`);
  console.log(`✓ Dynamics 365 configured: ${!!DYNAMICS_CONFIG.TENANT_ID}`);
  console.log(`\n🌐 ERP API is ready to accept connections!\n`);
});

export default app;