import { render, screen, fireEvent } from '@testing-library/react';
import { Field } from './Field';
import { TranscriptSegment } from '../types';

describe('Field', () => {
  const segments: TranscriptSegment[] = [
    {
      id: '1',
      content: 'Meet Alex tomorrow at 10:30',
      timestamp: Date.now(),
      isFinal: true,
      origin: 'voice',
      hasCode: false,
    },
  ];

  it('renders semantic highlights and opens focus overlay', () => {
    render(<Field segments={segments} liveText="" status="listening" />);

    const entity = screen.getByRole('button', { name: /alex/i });
    fireEvent.click(entity);

    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getByText('Alex')).toBeInTheDocument();
  });
});
