import { NextRequest, NextResponse } from 'next/server';
import {
  getIOCs,
  getIOCByValue,
  createIOC,
  updateIOC,
  deleteIOC,
  getAnalysesByIOC,
  getAlerts,
  getStoreStats
} from '@/lib/store';

// IOC CRUD Operations - Full in-memory database management
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const type = searchParams.get('type');
  const status = searchParams.get('status');
  const severity = searchParams.get('severity');
  const search = searchParams.get('search');
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '50');
  
  try {
    const result = await getIOCs({
      type,
      status,
      severity,
      search,
      page,
      limit
    });
    
    // Enrich with analyses and alerts
    const enrichedData = await Promise.all(result.data.map(async (ioc) => ({
      ...ioc,
      tags: ioc.tags || [],
      analyses: await getAnalysesByIOC(ioc.id),
      alerts: await getAlerts({ iocId: ioc.id, status: 'ACTIVE' })
    })));
    
    return NextResponse.json({
      success: true,
      data: enrichedData,
      pagination: result.pagination,
      stats: getStoreStats(),
      message: `Found ${result.total} IOC(s)`
    });
    
  } catch (error) {
    console.error('IOC List Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to fetch IOCs',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}

// Create new IOC
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { type, value, description, severity, confidence, tags, source } = body;
    
    if (!type || !value) {
      return NextResponse.json({ 
        success: false,
        error: 'Type and value are required',
        validTypes: ['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'CVE']
      }, { status: 400 });
    }
    
    // Check if already exists
    const existing = await getIOCByValue(value);
    if (existing) {
      return NextResponse.json({ 
        success: false,
        error: 'IOC already exists',
        existingId: existing.id,
        existingValue: existing.value
      }, { status: 409 });
    }
    
    const ioc = await createIOC({
      type,
      value,
      description: description || `${type}: ${value}`,
      severity: severity || 'MEDIUM',
      confidence: confidence || 50,
      source: source || 'manual',
      tags: tags || []
    });
    
    return NextResponse.json({ 
      success: true, 
      ioc,
      message: `IOC ${value} created successfully`
    }, { status: 201 });
    
  } catch (error: any) {
    console.error('Create IOC Error:', error);
    return NextResponse.json({ 
      success: false,
      error: error.message || 'Failed to create IOC',
      details: error.message
    }, { status: 500 });
  }
}

// Update IOC
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { id, description, severity, status, confidence, tags } = body;
    
    if (!id) {
      return NextResponse.json({ 
        success: false,
        error: 'IOC ID is required for update' 
      }, { status: 400 });
    }
    
    const ioc = await updateIOC(id, {
      description,
      severity,
      status,
      confidence,
      tags
    });
    
    if (!ioc) {
      return NextResponse.json({ 
        success: false,
        error: 'IOC not found' 
      }, { status: 404 });
    }
    
    return NextResponse.json({ 
      success: true, 
      ioc,
      message: `IOC ${ioc.value} updated successfully`
    });
    
  } catch (error: any) {
    console.error('Update IOC Error:', error);
    return NextResponse.json({ 
      success: false,
      error: error.message || 'Failed to update IOC',
      details: error.message
    }, { status: 500 });
  }
}

// Delete IOC
export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');
  
  if (!id) {
    return NextResponse.json({ 
      success: false,
      error: 'IOC ID is required for deletion' 
    }, { status: 400 });
  }
  
  try {
    const deleted = await deleteIOC(id);
    
    if (!deleted) {
      return NextResponse.json({ 
        success: false,
        error: 'IOC not found or already deleted' 
      }, { status: 404 });
    }
    
    return NextResponse.json({ 
      success: true, 
      message: 'IOC deleted successfully'
    });
    
  } catch (error: any) {
    console.error('Delete IOC Error:', error);
    return NextResponse.json({ 
      success: false,
      error: error.message || 'Failed to delete IOC',
      details: error.message
    }, { status: 500 });
  }
}
