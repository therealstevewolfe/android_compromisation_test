import { ChangeEvent } from 'react';

interface FileUploaderProps {
  onFileLoaded: (content: string) => void;
  onSampleRequested: () => void;
}

export const FileUploader = ({ onFileLoaded, onSampleRequested }: FileUploaderProps) => {
  const handleFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      return;
    }

    const text = await file.text();
    onFileLoaded(text);
    event.target.value = '';
  };

  return (
    <div className="upload-area">
      <label htmlFor="report-file">
        <span role="img" aria-label="upload">📁</span>
        Upload JSON Report
      </label>
      <input id="report-file" type="file" accept="application/json" onChange={handleFileChange} />
      <button type="button" onClick={onSampleRequested}>
        <span role="img" aria-label="sparkles">✨</span>
        Load Sample Report
      </button>
    </div>
  );
};
