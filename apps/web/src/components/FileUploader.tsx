import { X } from 'lucide-react';
import React, { useCallback, useRef, useState } from 'react';

type FileUploaderProps = {
  onFileSelected: (file: File | null) => void;
  maxBytes?: number;
  disabled?: boolean;
  compact?: boolean;
};

export function FileUploader({
  onFileSelected,
  maxBytes = 10 * 1024 * 1024,
  disabled = false,
  compact = false,
}: FileUploaderProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragActive, setDragActive] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);

  const validate = useCallback(
    (candidate: File) => {
      if (candidate.size === 0) return 'File must not be empty.';
      if (candidate.size > maxBytes) return 'File exceeds the size limit.';
      return null;
    },
    [maxBytes],
  );

  const handleFiles = useCallback(
    (files: FileList | null) => {
      setError(null);
      if (!files || files.length === 0) return;
      const candidate = files[0];
      const validationError = validate(candidate);
      if (validationError) {
        setError(validationError);
        setFile(null);
        onFileSelected(null);
        return;
      }
      setFile(candidate);
      onFileSelected(candidate);
    },
    [onFileSelected, validate],
  );

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      event.stopPropagation();
      setDragActive(false);
      if (!disabled) handleFiles(event.dataTransfer.files);
    },
    [disabled, handleFiles],
  );

  const openPicker = useCallback(() => {
    if (!disabled) inputRef.current?.click();
  }, [disabled]);

  const remove = useCallback(() => {
    setFile(null);
    setError(null);
    onFileSelected(null);
    if (inputRef.current) inputRef.current.value = '';
  }, [onFileSelected]);

  return (
    <div className="grid gap-3">
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        onClick={(event) => event.stopPropagation()}
        onChange={(event) => handleFiles(event.target.files)}
        disabled={disabled}
      />

      {!file && (
        <div
          role="button"
          tabIndex={disabled ? -1 : 0}
          aria-disabled={disabled}
          aria-label="Upload file"
          data-active={dragActive}
          onClick={openPicker}
          onKeyDown={(event) => {
            if (!disabled && (event.key === 'Enter' || event.key === ' ')) {
              event.preventDefault();
              openPicker();
            }
          }}
          onDrop={onDrop}
          onDragOver={(event) => {
            event.preventDefault();
            event.stopPropagation();
            if (!disabled) setDragActive(true);
          }}
          onDragLeave={(event) => {
            event.preventDefault();
            event.stopPropagation();
            setDragActive(false);
          }}
          className="dropzone"
        >
          <div className="dropzone__copy">
            <div className="dropzone__title">Select a file</div>
            <div className="dropzone__meta">
              Single file · Maximum {formatMiB(maxBytes)}
            </div>
          </div>
          <span className="button button--secondary" aria-hidden="true">
            Choose file
          </span>
        </div>
      )}

      {error && (
        <div role="alert" className="upload-error">
          {error}
        </div>
      )}

      {file && (
        <div className="upload-selected" data-compact={compact}>
          <div className="upload-selected__identity">
            <div className="min-w-0">
              <div className="upload-selected__name" title={file.name}>
                {file.name}
              </div>
              <div className="upload-selected__meta">
                {formatBytes(file.size)} / ready for analysis
              </div>
            </div>
          </div>
          <div className="flex flex-none items-center gap-1">
            {compact && (
              <button
                type="button"
                onClick={openPicker}
                disabled={disabled}
                className="button button--quiet"
              >
                Choose another
              </button>
            )}
            <button
              type="button"
              onClick={remove}
              disabled={disabled}
              className="button button--quiet"
              aria-label="Remove"
            >
              <X size={15} aria-hidden="true" />
              <span className="max-[430px]:sr-only">Remove</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function formatMiB(bytes: number): string {
  return `${bytes / (1024 * 1024)} MiB`;
}
function formatBytes(bytes: number): string {
  return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KiB`;
}
