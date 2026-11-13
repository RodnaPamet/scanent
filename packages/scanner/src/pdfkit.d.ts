/**
 * The part of pdfkit's API that `report-pdf.ts` uses. pdfkit ships no
 * declarations; this names only what is called, so a call outside it is a
 * type error rather than an assumption.
 */
declare module 'pdfkit' {
    interface PDFTextOptions {
        width?: number;
        height?: number;
        align?: 'left' | 'center' | 'right' | 'justify';
        lineBreak?: boolean;
        continued?: boolean;
        lineGap?: number;
        paragraphGap?: number;
        indent?: number;
    }
    interface PDFPage {
        readonly width: number;
        readonly height: number;
        margins: { top: number; bottom: number; left: number; right: number };
    }
    interface PDFDocumentOptions {
        size?: string | [number, number];
        layout?: 'portrait' | 'landscape';
        margins?: { top: number; bottom: number; left: number; right: number };
        autoFirstPage?: boolean;
        bufferPages?: boolean;
        compress?: boolean;
        info?: Record<string, string | Date>;
        pdfVersion?: string;
        displayTitle?: boolean;
        lang?: string;
    }
    class PDFDocument {
        constructor(options?: PDFDocumentOptions);
        x: number;
        y: number;
        readonly page: PDFPage;
        addPage(options?: Pick<PDFDocumentOptions, 'size' | 'layout' | 'margins'>): this;
        font(name: string): this;
        fontSize(size: number): this;
        fillColor(color: string): this;
        strokeColor(color: string): this;
        lineWidth(width: number): this;
        text(text: string, x?: number, y?: number, options?: PDFTextOptions): this;
        text(text: string, options?: PDFTextOptions): this;
        heightOfString(text: string, options?: PDFTextOptions): number;
        widthOfString(text: string, options?: PDFTextOptions): number;
        moveDown(lines?: number): this;
        rect(x: number, y: number, w: number, h: number): this;
        moveTo(x: number, y: number): this;
        lineTo(x: number, y: number): this;
        fill(color?: string): this;
        stroke(color?: string): this;
        bufferedPageRange(): { start: number; count: number };
        switchToPage(n: number): this;
        end(): void;
        read(): Buffer | null;
    }
    export = PDFDocument;
}
