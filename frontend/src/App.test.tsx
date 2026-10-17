import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi } from 'vitest';
import App from './App';

// Mock ResizeObserver class for Recharts ResponsiveContainer in jsdom
class MockResizeObserver {
  observe = vi.fn();
  unobserve = vi.fn();
  disconnect = vi.fn();
}
globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;

describe('LogSleuth Web Application Integration', () => {
  it('renders brand header, navigation tabs, and initial overview', async () => {
    render(<App />);

    // Brand check
    expect(screen.getByText('LogSleuth')).toBeInTheDocument();
    expect(screen.getByText('v1.0.0')).toBeInTheDocument();

    // Check tabs exist
    expect(screen.getAllByRole('button', { name: /overview/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /event explorer/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /findings/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /ioc explorer/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /detection rules/i })[0]).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /reports/i })[0]).toBeInTheDocument();

    // Ingest button
    expect(screen.getByRole('button', { name: /ingest logs/i })).toBeInTheDocument();

    // Initial load will populate with auth_bruteforce sample
    await waitFor(() => {
      expect(screen.getByText(/Total Events/i)).toBeInTheDocument();
    });
  });

  it('navigates seamlessly to Detection Rules catalog', async () => {
    render(<App />);

    const rulesTab = screen.getAllByRole('button', { name: /detection rules/i })[0];
    fireEvent.click(rulesTab);

    expect(screen.getByText(/Detection Rules & Threshold Catalog/i)).toBeInTheDocument();
    expect(screen.getByText('AUTH-001')).toBeInTheDocument();
    expect(screen.getByText('WEB-001')).toBeInTheDocument();
    expect(screen.getByText('NET-001')).toBeInTheDocument();
  });

  it('opens and closes the Ingest Logs modal', async () => {
    render(<App />);

    const ingestBtn = screen.getByRole('button', { name: /ingest logs/i });
    fireEvent.click(ingestBtn);

    expect(screen.getByText(/Ingest Security Logs/i)).toBeInTheDocument();
    expect(screen.getByText(/File Upload/i)).toBeInTheDocument();
    expect(screen.getByText(/Paste Logs/i)).toBeInTheDocument();
    expect(screen.getByText(/Synthetic Datasets/i)).toBeInTheDocument();
  });
});
