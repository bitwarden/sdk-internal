// Hand-written support code for the generated bindings in `BitwardenSdk`. Referenced from the
// `NaiveDate` custom type conversion configured in `bitwarden-core/uniffi.toml`.

import Foundation

public struct InvalidNaiveDateError: Error {}

public enum NaiveDateFormatter {
    private static let formatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.isLenient = false
        return formatter
    }()

    public static func date(from string: String) throws -> Date {
        guard let date = formatter.date(from: string) else {
            throw InvalidNaiveDateError()
        }
        return date
    }

    public static func string(from date: Date) -> String {
        formatter.string(from: date)
    }
}
