import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import ZAI from 'z-ai-web-dev-sdk';

// REAL AI Analysis using z-ai-web-dev-sdk
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, type, context } = body;
    
    if (!target || !type) {
      return NextResponse.json({ 
        error: 'Target and type are required',
        validTypes: ['ip', 'domain', 'hash', 'cve', 'general']
      }, { status: 400 });
    }
    
    // Initialize ZAI SDK
    const zai = await ZAI.create();
    
    // Build the prompt based on analysis type
    const systemPrompt = `You are an expert OSINT (Open Source Intelligence) and Cyber Threat Intelligence analyst. 
Analyze the provided target and provide actionable intelligence.

Your response MUST be structured as valid JSON with these fields:
{
  "summary": "Brief executive summary of findings",
  "threatLevel": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "confidence": 0-100,
  "keyFindings": ["finding1", "finding2", ...],
  "indicators": [{"type": "IP|DOMAIN|HASH|URL", "value": "...", "context": "..."}],
  "recommendations": ["actionable recommendation"],
  "sources": ["source1", "source2"]
}

Be specific, factual, and professional. If you cannot verify information, state uncertainty clearly.`;

    const userPrompt = `Perform OSINT analysis on the following target:

Type: ${type.toUpperCase()}
Target: ${target}
${context ? `Additional Context: ${context}` : ''}

Provide comprehensive threat intelligence including:
1. Geolocation and network info (if IP/domain)
2. Known malicious associations
3. Threat actor attribution if applicable
4. Recommended actions for security teams`;

    const completion = await zai.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt }
      ],
      temperature: 0.3,
      max_tokens: 2000
    });
    
    const aiContent = completion.choices[0]?.message?.content || '';
    
    let analysisResult;
    try {
      // Parse the JSON response from AI
      const jsonMatch = aiContent.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        analysisResult = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error('No JSON found in response');
      }
    } catch (parseError) {
      analysisResult = {
        summary: aiContent.substring(0, 500),
        threatLevel: 'MEDIUM',
        confidence: 60,
        keyFindings: [aiContent],
        indicators: [],
        recommendations: ['Manual review required'],
        sources: ['AI-Analysis']
      };
    }
    
    // Save to database
    let iocId: string | null = null;
    try {
      const ioc = await db.iOC.upsert({
        where: { value: target },
        update: { lastUpdated: new Date() },
        create: {
          type: mapTypeToIOC(type),
          value: target,
          description: analysisResult.summary?.substring(0, 500),
          severity: analysisResult.threatLevel || 'MEDIUM',
          confidence: analysisResult.confidence || 50,
          status: mapThreatToStatus(analysisResult.threatLevel),
          source: 'AI-Analysis',
          rawResponse: JSON.stringify(analysisResult)
        }
      });
      iocId = ioc.id;
      
      // Create analysis record
      await db.analysis.create({
        data: {
          iocId: ioc.id,
          source: 'z-ai-web-dev-sdk',
          sourceType: 'AI_ANALYSIS',
          rawData: JSON.stringify(analysisResult),
          summary: analysisResult.summary,
          findings: JSON.stringify(analysisResult.keyFindings || []),
          verified: false
        }
      });
      
      // Create alert if high severity
      if (['CRITICAL', 'HIGH'].includes(analysisResult.threatLevel || '')) {
        await db.alert.create({
          data: {
            iocId: ioc.id,
            title: `AI Alert: ${analysisResult.threatLevel} - ${target}`,
            description: analysisResult.summary,
            severity: analysisResult.threatLevel as any,
            type: 'ANOMALY_DETECTED'
          }
        });
      }
    } catch (dbError) {
      console.error('DB save error (non-critical):', dbError);
    }
    
    return NextResponse.json({
      success: true,
      source: 'z-ai-web-dev-sdk',
      timestamp: new Date().toISOString(),
      fetchedLive: true,
      iocId,
      analysis: analysisResult,
      rawAIResponse: aiContent
    });
    
  } catch (error) {
    console.error('AI Analysis Error:', error);
    return NextResponse.json({
      success: false,
      error: 'Failed to perform AI analysis',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 502 });
  }
}

function mapTypeToIOC(type: string): string {
  const mapping: Record<string, string> = {
    ip: 'IP',
    domain: 'DOMAIN',
    hash: 'HASH',
    cve: 'CVE',
    url: 'URL',
    email: 'EMAIL'
  };
  return mapping[type.toLowerCase()] || 'IP';
}

function mapThreatToStatus(threatLevel?: string): string {
  const mapping: Record<string, string> = {
    CRITICAL: 'MALICIOUS',
    HIGH: 'SUSPICIOUS',
    MEDIUM: 'SUSPICIOUS',
    LOW: 'UNKNOWN',
    INFO: 'BENIGN'
  };
  return mapping[threatLevel || ''] || 'UNKNOWN';
}
