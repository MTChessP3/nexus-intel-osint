import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

// IOC CRUD Operations - Full database management
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const type = searchParams.get('type');
  const status = searchParams.get('status');
  const severity = searchParams.get('severity');
  const search = searchParams.get('search');
  const page = parseInt(searchParams.get('page') || '1');
  const limit = parseInt(searchParams.get('limit') || '50');
  
  try {
    const where: any = {};
    
    if (type) where.type = type.toUpperCase();
    if (status) where.status = status.toUpperCase();
    if (severity) where.severity = severity.toUpperCase();
    if (search) {
      where.OR = [
        { value: { contains: search } },
        { description: { contains: search } },
        { source: { contains: search } }
      ];
    }
    
    const [iocs, total] = await Promise.all([
      db.iOC.findMany({
        where,
        orderBy: { lastUpdated: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
        include: {
          analyses: {
            orderBy: { timestamp: 'desc' },
            take: 3
          },
          alerts: {
            where: { status: 'ACTIVE' },
            orderBy: { createdAt: 'desc' },
            take: 5
          }
        }
      }),
      db.iOC.count({ where })
    ]);
    
    return NextResponse.json({
      success: true,
      data: iocs.map(ioc => ({
        ...ioc,
        tags: JSON.parse(ioc.tags || '[]'),
        analyses: ioc.analyses.map(a => ({
          ...a,
          findings: JSON.parse(a.findings || '[]')
        }))
      })),
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
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
        error: 'Type and value are required', 
        validTypes: ['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL', 'CVE'] 
      }, { status: 400 });
    }
    
    const existing = await db.iOC.findUnique({ where: { value } });
    if (existing) {
      return NextResponse.json({ 
        error: 'IOC already exists', 
        existingId: existing.id 
      }, { status: 409 });
    }
    
    const ioc = await db.iOC.create({
      data: {
        type: type.toUpperCase(),
        value,
        description: description || `${type}: ${value}`,
        severity: (severity || 'MEDIUM').toUpperCase(),
        confidence: confidence || 50,
        status: 'UNKNOWN',
        source: source || 'manual',
        tags: JSON.stringify(tags || [])
      }
    });
    
    // Create alert for new IOC
    await db.alert.create({
      data: {
        iocId: ioc.id,
        title: `New ${type} Added: ${value}`,
        description: description || `Manually added indicator of compromise`,
        severity: (severity || 'MEDIUM').toUpperCase() as any,
        type: 'IOC_DETECTED'
      }
    });
    
    return NextResponse.json({ success: true, ioc }, { status: 201 });
    
  } catch (error) {
    console.error('Create IOC Error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Failed to create IOC',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}

// Update IOC
export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    const { id, description, severity, status, confidence, tags } = body;
    
    if (!id) {
      return NextResponse.json({ error: 'IOC ID is required' }, { status: 400 });
    }
    
    const updateData: any = { lastUpdated: new Date() };
    if (description !== undefined) updateData.description = description;
    if (severity) updateData.severity = severity.toUpperCase();
    if (status) updateData.status = status.toUpperCase();
    if (confidence !== undefined) updateData.confidence = confidence;
    if (tags !== undefined) updateData.tags = JSON.stringify(tags);
    
    const ioc = await db.iOC.update({
      where: { id },
      data: updateData
    });
    
    return NextResponse.json({ success: true, ioc });
    
  } catch (error) {
    console.error('Update IOC Error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Failed to update IOC',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}

// Delete IOC
export async function DELETE(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const id = searchParams.get('id');
  
  if (!id) {
    return NextResponse.json({ error: 'IOC ID is required' }, { status: 400 });
  }
  
  try {
    // Delete related records first
    await db.analysis.deleteMany({ where: { iocId: id } });
    await db.alert.deleteMany({ where: { iocId: id } });
    await db.iOC.delete({ where: { id } });
    
    return NextResponse.json({ success: true, message: 'IOC deleted successfully' });
    
  } catch (error) {
    console.error('Delete IOC Error:', error);
    return NextResponse.json({ 
      success: false, 
      error: 'Failed to delete IOC',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
