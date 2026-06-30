import CoreImage
import Foundation
import Vision

struct CaptchaRecognition {
    let text: String
    let confidence: Float

    var isReliable: Bool {
        text.count == 4 && confidence >= 0.72
    }

    var isComplete: Bool {
        text.count == 4
    }
}

final class CaptchaService {
    private static let allowedCharacters = CharacterSet.alphanumerics

    static func recognize(imageData: Data) -> String? {
        guard let result = recognizeDetailed(imageData: imageData), result.isReliable else {
            return nil
        }
        return result.text
    }

    static func recognizeDetailed(imageData: Data) -> CaptchaRecognition? {
        guard let ciImage = CIImage(data: imageData) else { return nil }

        let variants = preprocessVariants(ciImage)
        var best: CaptchaRecognition?

        for variant in variants {
            let request = VNRecognizeTextRequest()
            request.recognitionLevel = .accurate
            request.usesLanguageCorrection = false
            request.minimumTextHeight = 0.18
            request.recognitionLanguages = ["en-US"]

            let handler = VNImageRequestHandler(ciImage: variant, options: [:])
            do {
                try handler.perform([request])
            } catch {
                Logger.write("[ERROR] Captcha OCR failed: \(error)")
                continue
            }

            for observation in request.results ?? [] {
                for candidate in observation.topCandidates(6) {
                    guard let normalized = normalize(candidate.string) else { continue }
                    let currentScore = score(text: normalized, confidence: candidate.confidence)
                    if best == nil || currentScore > score(text: best!.text, confidence: best!.confidence) {
                        best = CaptchaRecognition(text: normalized, confidence: candidate.confidence)
                    }
                }
            }
        }

        if let best {
            Logger.write("[INFO] Captcha OCR candidate: \(best.text) (\(best.confidence))")
        }
        return best
    }

    private static func preprocessVariants(_ input: CIImage) -> [CIImage] {
        let scaled = input.transformed(by: CGAffineTransform(scaleX: 4, y: 4))
        let grayscale = scaled.applyingFilter("CIColorControls", parameters: [
            kCIInputSaturationKey: 0,
            kCIInputContrastKey: 1.6,
            kCIInputBrightnessKey: 0.04
        ])
        let strongContrast = grayscale.applyingFilter("CIColorControls", parameters: [
            kCIInputSaturationKey: 0,
            kCIInputContrastKey: 2.7,
            kCIInputBrightnessKey: 0.08
        ])
        let sharpened = strongContrast.applyingFilter("CISharpenLuminance", parameters: [
            kCIInputSharpnessKey: 0.6
        ])
        let noisedDown = sharpened.applyingFilter("CIMedianFilter")

        return [
            scaled,
            grayscale,
            strongContrast,
            sharpened,
            noisedDown
        ]
    }

    private static func normalize(_ raw: String) -> String? {
        let mapped = raw
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: "_", with: "")
            .replacingOccurrences(of: "—", with: "")
            .replacingOccurrences(of: "–", with: "")
            .map { character -> Character? in
                let scalarText = String(character)
                if scalarText.rangeOfCharacter(from: allowedCharacters.inverted) == nil {
                    return character
                }
                return nil
            }
            .compactMap { $0 }

        let text = String(mapped).prefix(6)
        guard text.count >= 3 else { return nil }
        if text.count == 4 {
            return String(text)
        }
        return bestFourCharacters(in: String(text))
    }

    private static func bestFourCharacters(in text: String) -> String? {
        guard text.count > 4 else { return text.isEmpty ? nil : text }
        let characters = Array(text)
        let preferred = characters.filter { $0.isLetter || $0.isNumber }
        guard preferred.count >= 4 else { return nil }
        return String(preferred.prefix(4))
    }

    private static func score(text: String, confidence: Float) -> Float {
        let lengthScore: Float
        switch text.count {
        case 4:
            lengthScore = 0.35
        case 3, 5:
            lengthScore = 0.08
        default:
            lengthScore = -0.25
        }
        let diversityPenalty: Float = Set(text).count <= 2 ? 0.08 : 0
        return confidence + lengthScore - diversityPenalty
    }
}
