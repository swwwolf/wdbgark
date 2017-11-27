#ifndef BPRINTER_TABLE_PRINTER_H_
#define BPRINTER_TABLE_PRINTER_H_

#include <engextcpp.hpp>

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>

#include "..\..\..\manipulators.hpp"

namespace bprinter {

class endl {};

/** \class TablePrinter

Print a pretty table into your output of choice.

Usage:
TablePrinter tp(&std::cout);
tp.AddColumn("Name", 25);
tp.AddColumn("Age", 3);
tp.AddColumn("Position", 30);

tp.PrintHeader();
tp << "Dat Chu" << 25 << "Research Assistant";
tp << "John Doe" << 26 << "Professional Anonymity";
tp << "Jane Doe" << tp.SkipToNextLine();
tp << "Tom Doe" << 7 << "Student";
tp.PrintFooter();

\todo Add support for padding in each table cell
*/
class TablePrinter {
 public:
    explicit TablePrinter(std::ostream* output, const std::string &separator = "|");
    ~TablePrinter();

    size_t get_num_columns() const;
    size_t get_table_width() const;
    void set_separator(const std::string &separator);

    void AddColumn(const std::string &header_name, const size_t column_width);
    void PrintHeader();
    void PrintFooter();

    void flush_out() { *this << bprinter::endl(); *m_out_stream << wa::endlout; }
    void flush_warn() { *this << bprinter::endl(); *m_out_stream << wa::endlwarn; }
    void flush_err() { *this << bprinter::endl(); *m_out_stream << wa::endlerr; }

    TablePrinter& operator<<(endl) {
        while ( m_j != 0 ) {
            *this << "";
        }

        return *this;
    }

    // Can we merge these?
    TablePrinter& operator<<(float input);
    TablePrinter& operator<<(double input);

    template<typename T> TablePrinter& operator<<(T input) {
        if ( m_j == 0 ) {
            *m_out_stream << "|";
        }

        // Leave 3 extra space: One for negative sign, one for zero, one for decimal
        *m_out_stream << std::setw(m_column_widths.at(m_j)) << input;

        if ( m_j == get_num_columns() - 1 ) {
            *m_out_stream << "|";
            ++m_i;
            m_j = 0;
        } else {
            *m_out_stream << m_separator;
            ++m_j;
        }

        return *this;
    }

 private:
    void PrintHorizontalLine();

    template<typename T> void OutputDecimalNumber(T input);

 private:
    std::ostream* m_out_stream = nullptr;
    std::vector<std::string> m_column_headers{};
    std::vector<size_t> m_column_widths{};
    std::string m_separator{};

    size_t m_i = 0;   // index of current row
    size_t m_j = 0;   // index of current column
    size_t m_table_width = 0;

    size_t m_column_width_min = 4;
};

}   // namespace bprinter

#include "impl/table_printer.tpp.h"
#endif
