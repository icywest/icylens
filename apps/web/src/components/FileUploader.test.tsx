import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { FileUploader } from './FileUploader';

describe('FileUploader', () => {
  it('selects and removes a valid file', async () => {
    const user = userEvent.setup();
    const onFileSelected = vi.fn();
    const { container } = render(
      <FileUploader onFileSelected={onFileSelected} />,
    );
    const input = container.querySelector('input[type="file"]');
    expect(input).toBeInstanceOf(HTMLInputElement);

    const file = new File(['sample'], 'sample.bin', {
      type: 'application/octet-stream',
    });
    await user.upload(input as HTMLInputElement, file);
    expect(onFileSelected).toHaveBeenLastCalledWith(file);

    await user.click(screen.getByRole('button', { name: 'Remove' }));
    expect(onFileSelected).toHaveBeenLastCalledWith(null);
  });

  it.each([
    [new File([''], 'empty.bin'), 'File must not be empty.'],
    [new File(['too large'], 'large.bin'), 'File exceeds the size limit.'],
  ])('rejects an invalid file', async (file, message) => {
    const user = userEvent.setup();
    const onFileSelected = vi.fn();
    const { container } = render(
      <FileUploader onFileSelected={onFileSelected} maxBytes={4} />,
    );
    const input = container.querySelector('input[type="file"]');

    await user.upload(input as HTMLInputElement, file);

    expect(screen.getByRole('alert')).toHaveTextContent(message);
    expect(onFileSelected).toHaveBeenLastCalledWith(null);
  });

  it('supports drag and drop and keyboard activation', () => {
    const onFileSelected = vi.fn();
    const { container } = render(
      <FileUploader onFileSelected={onFileSelected} />,
    );
    const dropzone = screen.getByRole('button', { name: 'Upload file' });
    const input = container.querySelector('input[type="file"]');
    const click = vi.spyOn(input as HTMLInputElement, 'click');

    fireEvent.keyDown(dropzone, { key: 'Enter' });
    expect(click).toHaveBeenCalledOnce();

    const file = new File(['sample'], 'dropped.bin');
    fireEvent.drop(dropzone, { dataTransfer: { files: [file] } });
    expect(onFileSelected).toHaveBeenLastCalledWith(file);
  });
});
