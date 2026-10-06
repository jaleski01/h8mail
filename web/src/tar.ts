interface TarCallbacks {
    onStart: (name: string, size: number) => void;
    onData: (chunk: Uint8Array) => void;
    onEnd: () => void;
}

/** Read regular TAR entries without extracting paths or following archive links. */
export class TarTextReader {
    private header = new Uint8Array(512);
    private headerLength = 0;
    private remaining = 0;
    private padding = 0;
    private regular = false;
    private ended = false;

    constructor(private readonly callbacks: TarCallbacks) {}

    feed(chunk: Uint8Array): void {
        let offset = 0;
        while (offset < chunk.length && !this.ended) {
            if (this.remaining > 0) {
                const length = Math.min(this.remaining, chunk.length - offset);
                if (this.regular) this.callbacks.onData(chunk.subarray(offset, offset + length));
                this.remaining -= length;
                offset += length;
                if (!this.remaining && this.regular) this.callbacks.onEnd();
                continue;
            }
            if (this.padding > 0) {
                const length = Math.min(this.padding, chunk.length - offset);
                this.padding -= length;
                offset += length;
                continue;
            }
            const length = Math.min(512 - this.headerLength, chunk.length - offset);
            this.header.set(chunk.subarray(offset, offset + length), this.headerLength);
            this.headerLength += length;
            offset += length;
            if (this.headerLength === 512) this.readHeader();
        }
    }

    finish(): void {
        if (this.remaining || this.padding || this.headerLength) throw new Error('The TAR archive is incomplete.');
    }

    private readHeader(): void {
        this.headerLength = 0;
        if (this.header.every((byte) => byte === 0)) { this.ended = true; return; }
        const stringAt = (start: number, length: number): string => new TextDecoder().decode(this.header.subarray(start, start + length)).split('\0')[0]?.trim() ?? '';
        const sizeText = stringAt(124, 12);
        const checksumText = stringAt(148, 8);
        if (!/^[0-7]+$/.test(sizeText) || !/^[0-7]+$/.test(checksumText)) throw new Error('This TAR archive uses an unsupported or malformed header.');
        const size = Number.parseInt(sizeText, 8);
        const checksum = this.header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
        if (!Number.isSafeInteger(size) || checksum !== Number.parseInt(checksumText, 8)) throw new Error('The TAR header checksum is invalid.');
        const name = stringAt(0, 100);
        const prefix = stringAt(345, 155);
        const type = this.header[156];
        this.regular = type === 0 || type === 48 || type === 55;
        this.remaining = size;
        this.padding = (512 - (size % 512)) % 512;
        if (this.regular) {
            this.callbacks.onStart(prefix ? `${prefix}/${name}` : name, size);
            if (!size) this.callbacks.onEnd();
        }
    }
}
