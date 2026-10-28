import React, { useCallback, useRef, useState } from 'react';

type FileUploaderProps = {
  onFileSelected: (file: File | null) => void;
  maxBytes?: number;
  disabled?: boolean;
};

export function FileUploader({
  onFileSelected,
  maxBytes = 10 * 1024 * 1024,
  disabled = false,
}: FileUploaderProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);

  const validate = useCallback(
    (f: File) => {
      if (f.size === 0) return 'File must not be empty.';
      if (f.size > maxBytes) return 'File exceeds the size limit.';
      return null;
    },
    [maxBytes],
  );

  const handleFiles = useCallback(
    (files: FileList | null) => {
      setError(null);
      if (!files || files.length === 0) return;
      const f = files[0];
      const v = validate(f);
      if (v) {
        setError(v);
        setFile(null);
        onFileSelected(null);
        return;
      }
      setFile(f);
      onFileSelected(f);
    },
    [onFileSelected, validate],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDragActive(false);
      if (disabled) return;
      handleFiles(e.dataTransfer.files);
    },
    [disabled, handleFiles],
  );

  const onDragOver = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      if (!disabled) setDragActive(true);
    },
    [disabled],
  );

  const onDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
  }, []);

  const openPicker = useCallback(() => {
    if (disabled) return;
    inputRef.current?.click();
  }, [disabled]);

  const remove = useCallback(() => {
    setFile(null);
    setError(null);
    onFileSelected(null);
    if (inputRef.current) inputRef.current.value = '';
  }, [onFileSelected]);

  const dropzoneClass =
    'border border-neutral-800 rounded-md p-6 text-center transition-colors focus:outline-none focus-visible:ring-1 focus-visible:ring-neutral-400 ' +
    (dragActive ? 'bg-neutral-900/40 border-neutral-600' : 'bg-neutral-950') +
    ' ' +
    (disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer');

  return (
    <div className="space-y-3">
      <div
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        aria-label="Upload file"
        onClick={openPicker}
        onKeyDown={(e) => {
          if (disabled) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            openPicker();
          }
        }}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        className={dropzoneClass}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onClick={(event) => event.stopPropagation()}
          onChange={(e) => handleFiles(e.target.files)}
          disabled={disabled}
        />
        <div className="space-y-1">
          <div className="text-sm text-neutral-200">
            Drop a file here or click to select
          </div>
          <div className="text-xs text-neutral-500">
            Single file - Max {formatMiB(maxBytes)}
          </div>
        </div>
      </div>

      {error && (
        <div role="alert" className="text-xs text-red-400">
          {error}
        </div>
      )}

      {file && (
        <div className="flex items-center justify-between border border-neutral-800 rounded-md px-3 py-2">
          <div className="min-w-0">
            <div className="text-sm text-neutral-200 truncate">{file.name}</div>
            <div className="text-xs text-neutral-500">
              {(file.size / 1024).toFixed(1)} KiB
            </div>
          </div>
          <button
            type="button"
            onClick={remove}
            disabled={disabled}
            className="text-xs text-neutral-400 hover:text-neutral-200 disabled:opacity-50"
          >
            Remove
          </button>
        </div>
      )}
    </div>
  );
}

function formatMiB(bytes: number): string {
  return `${bytes / (1024 * 1024)} MiB`;
}
