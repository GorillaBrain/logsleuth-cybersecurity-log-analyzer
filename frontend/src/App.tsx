import React, { useState } from 'react';
import { AnalysisProvider, useAnalysis } from './context/AnalysisContext';
import { Navbar, type NavTab } from './components/layout/Navbar';
import { Footer } from './components/layout/Footer';
import { DashboardOverview } from './components/dashboard/DashboardOverview';
import { EventExplorer } from './components/events/EventExplorer';
import { FindingsWorkspace } from './components/findings/FindingsWorkspace';
import { IOCExplorer } from './components/iocs/IOCExplorer';
import { DetectionRulesPage } from './components/rules/DetectionRulesPage';
import { ReportView } from './components/reports/ReportView';
import { LogIngestionModal } from './components/ingestion/LogIngestionModal';
import { EventDetailModal } from './components/events/EventDetailModal';
import { EmptyState } from './components/common/EmptyState';
import type { ParsedEvent } from './types';
import { Loader2 } from 'lucide-react';

const MainContent: React.FC = () => {
  const { analysis, isLoading, error, setFilterState } = useAnalysis();
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [isIngestOpen, setIsIngestOpen] = useState(false);
  const [inspectedEvent, setInspectedEvent] = useState<ParsedEvent | null>(null);

  // Jump to Event Explorer with specific event IDs filtered
  const handleFilterEventsByFinding = (eventIds: string[]) => {
    // If there are specific event IDs, we can pre-filter or search
    if (analysis) {
      const matchedEvents = analysis.events.filter(e => eventIds.includes(e.id));
      if (matchedEvents.length > 0 && matchedEvents[0].source_ip) {
        setFilterState(prev => ({ ...prev, sourceIp: matchedEvents[0].source_ip! }));
      }
    }
    setCurrentTab('events');
  };

  const handleFilterByIndicator = (indicator: string) => {
    setFilterState(prev => ({ ...prev, search: indicator }));
    setCurrentTab('events');
  };

  return (
    <div className="min-h-screen bg-navy-950 text-gray-200 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      <Navbar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        onOpenIngest={() => setIsIngestOpen(true)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {error && (
          <div className="mb-6 p-4 bg-red-950/40 border border-red-500/40 rounded-xl text-xs text-red-300 font-mono">
            <strong>Error:</strong> {error}
          </div>
        )}

        {isLoading ? (
          <div className="flex flex-col items-center justify-center py-24 space-y-4">
            <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
            <p className="font-mono text-xs text-cyan-300 tracking-wider">
              PARSING LOG STREAM & EVALUATING DETECTION RULES...
            </p>
          </div>
        ) : !analysis && currentTab !== 'rules' ? (
          <EmptyState onOpenIngest={() => setIsIngestOpen(true)} />
        ) : (
          <>
            {currentTab === 'dashboard' && analysis && (
              <DashboardOverview
                onNavigateFindings={() => setCurrentTab('findings')}
                onNavigateEvents={() => setCurrentTab('events')}
                onSelectEvent={(e) => setInspectedEvent(e)}
                onOpenIngest={() => setIsIngestOpen(true)}
              />
            )}

            {currentTab === 'events' && analysis && (
              <EventExplorer events={analysis.events} />
            )}

            {currentTab === 'findings' && analysis && (
              <FindingsWorkspace
                findings={analysis.findings}
                onFilterEventsByFinding={handleFilterEventsByFinding}
              />
            )}

            {currentTab === 'iocs' && analysis && (
              <IOCExplorer
                iocs={analysis.iocs}
                onSelectIndicator={handleFilterByIndicator}
              />
            )}

            {currentTab === 'rules' && <DetectionRulesPage />}

            {currentTab === 'reports' && analysis && (
              <ReportView analysis={analysis} />
            )}
          </>
        )}
      </main>

      <Footer />

      {/* Log Ingestion Modal */}
      <LogIngestionModal
        isOpen={isIngestOpen}
        onClose={() => setIsIngestOpen(false)}
      />

      {/* Global Event Inspector Modal */}
      <EventDetailModal
        event={inspectedEvent}
        onClose={() => setInspectedEvent(null)}
      />
    </div>
  );
};

export function App() {
  return (
    <AnalysisProvider>
      <MainContent />
    </AnalysisProvider>
  );
}

export default App;
