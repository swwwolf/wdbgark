#include <bprinter/table_printer.h>

#include <stdexcept>
#include <iomanip>
#include <string>

namespace bprinter {

TablePrinter::TablePrinter(std::ostream* output, const std::string &separator) : m_out_stream(output),
                                                                                 m_separator(separator) {}

TablePrinter::~TablePrinter() {
    m_out_stream = nullptr;
}

size_t TablePrinter::get_num_columns() const {
    return m_column_headers.size();
}

size_t TablePrinter::get_table_width() const {
    return m_table_width;
}

void TablePrinter::set_separator(const std::string &separator) {
    m_separator = separator;
}

/** \brief Add a column to our table
**
** \param header_name Name to be print for the header
** \param column_width the width of the column (has to be >=5)
** */
void TablePrinter::AddColumn(const std::string &header_name, const size_t column_width) {
    if ( column_width < m_column_width_min ) {
        throw std::invalid_argument("Column size has to be >= 4");
    }

    m_column_headers.push_back(header_name);
    m_column_widths.push_back(column_width);
    m_table_width += column_width + m_separator.size();   // for the separator
}

void TablePrinter::PrintHorizontalLine() {
    *m_out_stream << "+";  // the left bar

    for ( size_t i = 0; i < m_table_width - 1; ++i ) {
        *m_out_stream << "-";
    }

    *m_out_stream << "+";  // the right bar
    flush_out();
}

void TablePrinter::PrintHeader() {
    PrintHorizontalLine();
    *m_out_stream << "|";

    for ( size_t i = 0; i < get_num_columns(); ++i ) {
        *m_out_stream << std::setw(m_column_widths.at(i)) << m_column_headers.at(i).substr(0, m_column_widths.at(i));

        if ( i != get_num_columns() - 1 ) {
            *m_out_stream << m_separator;
        }
    }

    *m_out_stream << "|";
    flush_out();
    PrintHorizontalLine();
}

void TablePrinter::PrintFooter() {
    PrintHorizontalLine();
}

TablePrinter& TablePrinter::operator<<(float input) {
    OutputDecimalNumber<float>(input);
    return *this;
}

TablePrinter& TablePrinter::operator<<(double input) {
    OutputDecimalNumber<double>(input);
    return *this;
}

}   // namespace bprinter
