import CoreGraphics
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

/// The image under the whole of FarSight: under the map, and through the map's
/// surfaces and the HUD's glass. One seamless tile, repeated across a plane
/// behind the map (BackdropLayout).
///
/// It comes in two forms. `image` is the backdrop as it is, for open ground
/// between instances. `frosted` is the same tile blurred, for the inside of an
/// instance's wall, which is a surface over the backdrop rather than a hole in
/// it. Both are dithered down to 8 bits from the 10 the file holds, so the long,
/// dark gradients do not band.
///
/// Readability rests on one number: no pixel is brighter than
/// `luminanceCap`. Over any backdrop under that cap, the connection lines,
/// labels and text that BackdropTests lists keep WCAG contrast on the
/// translucent surfaces in Theme; the exceptions it names, outlines and faded
/// lines among them, are not held to it. The bundled backdrop is painted under the cap, and a backdrop from
/// elsewhere would have to be brought under it before it is shown.
nonisolated struct Backdrop: Sendable {
    let image: CGImage
    let frosted: CGImage

    /// The brightest a backdrop pixel may be: relative luminance, linear
    /// Display P3.
    static let luminanceCap = 0.07

    /// How far the frosted form is blurred, as a share of the tile's side.
    static let frost = 0.012

    /// The file holds the tile with this many pixels of wrap on every side —
    /// the field continued past each edge — and the app crops it away. HEVC
    /// subsamples colour two to one and flattens a picture's last columns;
    /// without the margin that flattening would show as a seam at every tile
    /// edge.
    static let margin: CGFloat = 64

    /// The backdrop in `url`, read and prepared off the main thread. Nil if
    /// it cannot be read, and the map draws on its plain ground.
    static func load(from url: URL) async -> Backdrop? {
        await Task.detached(priority: .userInitiated) { prepare(url) }.value
    }

    static func prepare(_ url: URL) -> Backdrop? {
        guard let space = CGColorSpace(name: CGColorSpace.displayP3),
              let source = tile(from: url) else { return nil }
        let context = CIContext(options: [.cacheIntermediates: false])
        let side = source.extent.width

        // The frosted form needs a quarter of the side, a sixteenth of the
        // pixels, once blurred. It is reduced first, from the tile repeated,
        // so the filter wraps at the edges; the small tile is then repeated
        // and blurred, so the blur wraps too, and the full-size tile is never
        // blurred at all.
        let small = CGRect(x: 0, y: 0, width: (side / 4).rounded(), height: (side / 4).rounded())
        guard let repeated = repeating(source),
              let reduced = repeating(
                  repeated
                      .transformed(by: CGAffineTransform(scaleX: small.width / side, y: small.height / side), highQualityDownsample: true)
                      .cropped(to: small)
              ) else { return nil }
        let frosted = reduced.applyingGaussianBlur(sigma: frost * small.width).cropped(to: small)

        guard let image = render(source, source.extent, context, space),
              let frostedImage = render(frosted, small, context, space) else { return nil }
        return Backdrop(image: image, frosted: frostedImage)
    }

    /// The tile in `url`, its margin cropped away, at the origin.
    static func tile(from url: URL) -> CIImage? {
        guard let file = CIImage(contentsOf: url) else { return nil }
        let extent = file.extent
        guard extent.width == extent.height, extent.width - 2 * margin >= 64 else { return nil }
        return file
            .cropped(to: extent.insetBy(dx: margin, dy: margin))
            .transformed(by: CGAffineTransform(translationX: -extent.minX - margin, y: -extent.minY - margin))
    }

    /// The image repeated without end in both directions.
    private static func repeating(_ image: CIImage) -> CIImage? {
        let tiler = CIFilter.affineTile()
        tiler.inputImage = image
        tiler.transform = .identity
        return tiler.outputImage
    }

    /// 8-bit Display P3, dithered unless asked not to. The dither is applied
    /// to the encoded values that are about to be rounded, so it is the same
    /// half level at every brightness; in CoreImage's linear working space the
    /// same noise would be ten levels deep in the darkest folds.
    static func render(_ image: CIImage, _ extent: CGRect, _ context: CIContext, _ space: CGColorSpace, dither: Bool = true) -> CGImage? {
        var output = image
        if dither {
            guard let encoded = image.matchedFromWorkingSpace(to: space) else { return nil }
            let filter = CIFilter.dither()
            filter.inputImage = encoded
            filter.intensity = 0.008
            guard let dithered = filter.outputImage?.matchedToWorkingSpace(from: space) else { return nil }
            output = dithered
        }
        return context.createCGImage(output.cropped(to: extent), from: extent, format: .RGBA8, colorSpace: space)
    }
}
