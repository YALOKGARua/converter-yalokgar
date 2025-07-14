#include "main_window.hpp"
#include "../include/core/converter_engine.hpp"
#include "../include/modules/image/image_converter.hpp"
#include "../include/modules/video/video_converter.hpp"
#include "../include/modules/audio/audio_converter.hpp"
#include "../include/modules/document/document_converter.hpp"
#include "../include/modules/archive/archive_converter.hpp"
#include "../include/modules/data/data_converter.hpp"
#include <QtWidgets>
#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QProgressBar>
#include <QTextEdit>
#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QUrl>
#include <QThread>
#include <QTimer>
#include <QSplitter>
#include <QTabWidget>
#include <QTreeWidget>
#include <QTableWidget>
#include <QMenuBar>
#include <QStatusBar>
#include <QToolBar>
#include <QSettings>
#include <QMessageBox>
#include <QListWidget>
#include <QGroupBox>
#include <QSlider>
#include <QSpinBox>
#include <QCheckBox>
#include <QRadioButton>
#include <QButtonGroup>
#include <QScrollArea>
#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGraphicsPixmapItem>
#include <QMediaPlayer>
#include <QVideoWidget>
#include <QSplashScreen>
#include <QSystemTrayIcon>
#include <QNotificationManager>
#include <QDockWidget>
#include <QMdiArea>
#include <QMdiSubWindow>
#include <QCalendarWidget>
#include <QDateTimeEdit>
#include <QColorDialog>
#include <QFontDialog>
#include <QInputDialog>
#include <QWizard>
#include <QWizardPage>
#include <QPropertyAnimation>
#include <QGraphicsEffect>
#include <QParallelAnimationGroup>
#include <QSequentialAnimationGroup>
#include <QPainter>
#include <QPainterPath>
#include <QBrush>
#include <QPen>
#include <QGradient>
#include <QPixmap>
#include <QIcon>
#include <QMovie>
#include <QSvgRenderer>
#include <QSvgWidget>
#include <QWebEngineView>
#include <QWebEnginePage>
#include <QWebEngineProfile>
#include <QWebChannel>
#include <QQuickWidget>
#include <QQmlEngine>
#include <QQmlContext>
#include <QOpenGLWidget>
#include <QOpenGLFunctions>
#include <QMatrix4x4>
#include <QVector3D>
#include <QQuaternion>
#include <QChart>
#include <QChartView>
#include <QLineSeries>
#include <QBarSeries>
#include <QPieSeries>
#include <QScatterSeries>
#include <QAreaSeries>
#include <QSplineSeries>
#include <QCandlestickSeries>
#include <QBoxPlotSeries>

class ConversionWorker : public QObject {
    Q_OBJECT

public:
    ConversionWorker(const QString& input, const QString& output, const QString& format, QObject* parent = nullptr)
        : QObject(parent), input_file_(input), output_file_(output), target_format_(format) {}

public slots:
    void startConversion() {
        try {
            converter::core::ConversionEngine engine;
            
            std::vector<uint8_t> input_data;
            QFile file(input_file_);
            if (file.open(QIODevice::ReadOnly)) {
                QByteArray data = file.readAll();
                input_data.assign(data.begin(), data.end());
                file.close();
            }
            
            converter::core::ConversionOptions options;
            options.progress_callback = [this](float progress) {
                emit progressUpdated(static_cast<int>(progress * 100));
            };
            
            options.log_callback = [this](const std::string& message) {
                emit logMessage(QString::fromStdString(message));
            };
            
            auto result = engine.convert<std::vector<uint8_t>, std::vector<uint8_t>>(
                std::move(input_data), target_format_.toStdString(), options);
            
            if (result) {
                QFile output_file(output_file_);
                if (output_file.open(QIODevice::WriteOnly)) {
                    output_file.write(reinterpret_cast<const char*>(result->data()), result->size());
                    output_file.close();
                    emit conversionCompleted(true, "");
                } else {
                    emit conversionCompleted(false, "Failed to write output file");
                }
            } else {
                emit conversionCompleted(false, "Conversion failed");
            }
            
        } catch (const std::exception& e) {
            emit conversionCompleted(false, QString::fromStdString(e.what()));
        }
    }

signals:
    void progressUpdated(int percentage);
    void logMessage(const QString& message);
    void conversionCompleted(bool success, const QString& error);

private:
    QString input_file_;
    QString output_file_;
    QString target_format_;
};

class FileDropWidget : public QWidget {
    Q_OBJECT

public:
    FileDropWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setAcceptDrops(true);
        setMinimumSize(400, 300);
        
        auto layout = new QVBoxLayout(this);
        
        drop_label_ = new QLabel("Drag and drop files here or click to browse");
        drop_label_->setAlignment(Qt::AlignCenter);
        drop_label_->setStyleSheet(
            "QLabel {"
            "border: 2px dashed #aaa;"
            "border-radius: 10px;"
            "padding: 40px;"
            "font-size: 16px;"
            "color: #666;"
            "background-color: #f9f9f9;"
            "}"
        );
        
        layout->addWidget(drop_label_);
        
        connect(this, &FileDropWidget::clicked, this, &FileDropWidget::browseFiles);
    }

protected:
    void dragEnterEvent(QDragEnterEvent* event) override {
        if (event->mimeData()->hasUrls()) {
            event->acceptProposedAction();
            drop_label_->setStyleSheet(
                "QLabel {"
                "border: 2px dashed #4CAF50;"
                "border-radius: 10px;"
                "padding: 40px;"
                "font-size: 16px;"
                "color: #4CAF50;"
                "background-color: #e8f5e8;"
                "}"
            );
        }
    }

    void dragLeaveEvent(QDragLeaveEvent* event) override {
        drop_label_->setStyleSheet(
            "QLabel {"
            "border: 2px dashed #aaa;"
            "border-radius: 10px;"
            "padding: 40px;"
            "font-size: 16px;"
            "color: #666;"
            "background-color: #f9f9f9;"
            "}"
        );
    }

    void dropEvent(QDropEvent* event) override {
        const QMimeData* mimeData = event->mimeData();
        if (mimeData->hasUrls()) {
            QStringList files;
            for (const QUrl& url : mimeData->urls()) {
                if (url.isLocalFile()) {
                    files << url.toLocalFile();
                }
            }
            if (!files.isEmpty()) {
                emit filesDropped(files);
            }
        }
        
        dragLeaveEvent(nullptr);
    }

    void mousePressEvent(QMouseEvent* event) override {
        if (event->button() == Qt::LeftButton) {
            emit clicked();
        }
    }

private slots:
    void browseFiles() {
        QStringList files = QFileDialog::getOpenFileNames(
            this, "Select Files to Convert", QString(),
            "All Files (*.*);;Images (*.jpg *.jpeg *.png *.gif *.bmp *.tiff *.webp);;"
            "Videos (*.mp4 *.avi *.mov *.mkv *.wmv *.flv *.webm);;"
            "Audio (*.mp3 *.wav *.flac *.ogg *.aac *.m4a *.wma);;"
            "Documents (*.pdf *.docx *.doc *.xlsx *.xls *.pptx *.ppt);;"
            "Archives (*.zip *.rar *.tar *.gz *.7z *.bz2);;"
            "Data (*.json *.xml *.csv *.yaml *.toml)"
        );
        
        if (!files.isEmpty()) {
            emit filesDropped(files);
        }
    }

signals:
    void filesDropped(const QStringList& files);
    void clicked();

private:
    QLabel* drop_label_;
};

class ConversionOptionsWidget : public QWidget {
    Q_OBJECT

public:
    ConversionOptionsWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setupUI();
        connectSignals();
    }

    void setFormat(const QString& format) {
        current_format_ = format;
        updateOptionsForFormat();
    }

    QVariantMap getOptions() const {
        QVariantMap options;
        
        if (quality_slider_->isVisible()) {
            options["quality"] = quality_slider_->value();
        }
        
        if (width_spin_->isVisible()) {
            options["width"] = width_spin_->value();
        }
        
        if (height_spin_->isVisible()) {
            options["height"] = height_spin_->value();
        }
        
        if (bitrate_spin_->isVisible()) {
            options["bitrate"] = bitrate_spin_->value();
        }
        
        if (fps_spin_->isVisible()) {
            options["fps"] = fps_spin_->value();
        }
        
        if (sample_rate_combo_->isVisible()) {
            options["sample_rate"] = sample_rate_combo_->currentText().toInt();
        }
        
        if (channels_combo_->isVisible()) {
            options["channels"] = channels_combo_->currentText().toInt();
        }
        
        options["preserve_metadata"] = preserve_metadata_check_->isChecked();
        options["overwrite"] = overwrite_check_->isChecked();
        options["optimize"] = optimize_check_->isChecked();
        
        return options;
    }

private:
    void setupUI() {
        auto layout = new QVBoxLayout(this);
        
        auto scroll_area = new QScrollArea;
        auto scroll_widget = new QWidget;
        auto scroll_layout = new QVBoxLayout(scroll_widget);
        
        quality_group_ = new QGroupBox("Quality Settings");
        auto quality_layout = new QVBoxLayout(quality_group_);
        
        quality_slider_ = new QSlider(Qt::Horizontal);
        quality_slider_->setRange(1, 100);
        quality_slider_->setValue(75);
        quality_label_ = new QLabel("Quality: 75%");
        quality_layout->addWidget(quality_label_);
        quality_layout->addWidget(quality_slider_);
        
        dimensions_group_ = new QGroupBox("Dimensions");
        auto dimensions_layout = new QGridLayout(dimensions_group_);
        
        dimensions_layout->addWidget(new QLabel("Width:"), 0, 0);
        width_spin_ = new QSpinBox;
        width_spin_->setRange(1, 32000);
        width_spin_->setValue(1920);
        dimensions_layout->addWidget(width_spin_, 0, 1);
        
        dimensions_layout->addWidget(new QLabel("Height:"), 1, 0);
        height_spin_ = new QSpinBox;
        height_spin_->setRange(1, 32000);
        height_spin_->setValue(1080);
        dimensions_layout->addWidget(height_spin_, 1, 1);
        
        video_group_ = new QGroupBox("Video Settings");
        auto video_layout = new QGridLayout(video_group_);
        
        video_layout->addWidget(new QLabel("Bitrate (kbps):"), 0, 0);
        bitrate_spin_ = new QSpinBox;
        bitrate_spin_->setRange(100, 100000);
        bitrate_spin_->setValue(5000);
        video_layout->addWidget(bitrate_spin_, 0, 1);
        
        video_layout->addWidget(new QLabel("Frame Rate:"), 1, 0);
        fps_spin_ = new QDoubleSpinBox;
        fps_spin_->setRange(1.0, 120.0);
        fps_spin_->setValue(30.0);
        video_layout->addWidget(fps_spin_, 1, 1);
        
        audio_group_ = new QGroupBox("Audio Settings");
        auto audio_layout = new QGridLayout(audio_group_);
        
        audio_layout->addWidget(new QLabel("Sample Rate:"), 0, 0);
        sample_rate_combo_ = new QComboBox;
        sample_rate_combo_->addItems({"8000", "11025", "16000", "22050", "32000", "44100", "48000", "96000", "192000"});
        sample_rate_combo_->setCurrentText("44100");
        audio_layout->addWidget(sample_rate_combo_, 0, 1);
        
        audio_layout->addWidget(new QLabel("Channels:"), 1, 0);
        channels_combo_ = new QComboBox;
        channels_combo_->addItems({"1", "2", "4", "6", "8"});
        channels_combo_->setCurrentText("2");
        audio_layout->addWidget(channels_combo_, 1, 1);
        
        general_group_ = new QGroupBox("General Options");
        auto general_layout = new QVBoxLayout(general_group_);
        
        preserve_metadata_check_ = new QCheckBox("Preserve Metadata");
        preserve_metadata_check_->setChecked(true);
        general_layout->addWidget(preserve_metadata_check_);
        
        overwrite_check_ = new QCheckBox("Overwrite Existing Files");
        overwrite_check_->setChecked(false);
        general_layout->addWidget(overwrite_check_);
        
        optimize_check_ = new QCheckBox("Optimize Output");
        optimize_check_->setChecked(true);
        general_layout->addWidget(optimize_check_);
        
        scroll_layout->addWidget(quality_group_);
        scroll_layout->addWidget(dimensions_group_);
        scroll_layout->addWidget(video_group_);
        scroll_layout->addWidget(audio_group_);
        scroll_layout->addWidget(general_group_);
        scroll_layout->addStretch();
        
        scroll_area->setWidget(scroll_widget);
        scroll_area->setWidgetResizable(true);
        scroll_area->setMinimumWidth(300);
        
        layout->addWidget(scroll_area);
    }

    void connectSignals() {
        connect(quality_slider_, &QSlider::valueChanged, this, [this](int value) {
            quality_label_->setText(QString("Quality: %1%").arg(value));
        });
    }

    void updateOptionsForFormat() {
        bool is_image = current_format_.contains(QRegularExpression("jpg|jpeg|png|gif|bmp|tiff|webp", QRegularExpression::CaseInsensitiveOption));
        bool is_video = current_format_.contains(QRegularExpression("mp4|avi|mov|mkv|wmv|flv|webm", QRegularExpression::CaseInsensitiveOption));
        bool is_audio = current_format_.contains(QRegularExpression("mp3|wav|flac|ogg|aac|m4a|wma", QRegularExpression::CaseInsensitiveOption));
        
        quality_group_->setVisible(is_image || is_video || is_audio);
        dimensions_group_->setVisible(is_image || is_video);
        video_group_->setVisible(is_video);
        audio_group_->setVisible(is_audio || is_video);
    }

private:
    QString current_format_;
    
    QGroupBox* quality_group_;
    QSlider* quality_slider_;
    QLabel* quality_label_;
    
    QGroupBox* dimensions_group_;
    QSpinBox* width_spin_;
    QSpinBox* height_spin_;
    
    QGroupBox* video_group_;
    QSpinBox* bitrate_spin_;
    QDoubleSpinBox* fps_spin_;
    
    QGroupBox* audio_group_;
    QComboBox* sample_rate_combo_;
    QComboBox* channels_combo_;
    
    QGroupBox* general_group_;
    QCheckBox* preserve_metadata_check_;
    QCheckBox* overwrite_check_;
    QCheckBox* optimize_check_;
};

class ConversionQueueWidget : public QWidget {
    Q_OBJECT

public:
    ConversionQueueWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setupUI();
    }

    void addConversionTask(const QString& input, const QString& output, const QString& format) {
        int row = queue_table_->rowCount();
        queue_table_->insertRow(row);
        
        queue_table_->setItem(row, 0, new QTableWidgetItem(QFileInfo(input).fileName()));
        queue_table_->setItem(row, 1, new QTableWidgetItem(format.toUpper()));
        queue_table_->setItem(row, 2, new QTableWidgetItem("Queued"));
        
        auto progress_bar = new QProgressBar;
        progress_bar->setRange(0, 100);
        progress_bar->setValue(0);
        queue_table_->setCellWidget(row, 3, progress_bar);
        
        ConversionTask task;
        task.input_file = input;
        task.output_file = output;
        task.format = format;
        task.status = "Queued";
        task.progress = 0;
        task.row = row;
        
        tasks_.append(task);
        
        if (tasks_.size() == 1 && !is_processing_) {
            processNextTask();
        }
    }

    void clearCompleted() {
        for (int i = tasks_.size() - 1; i >= 0; --i) {
            if (tasks_[i].status == "Completed" || tasks_[i].status == "Failed") {
                queue_table_->removeRow(tasks_[i].row);
                tasks_.removeAt(i);
                
                for (int j = i; j < tasks_.size(); ++j) {
                    tasks_[j].row--;
                }
            }
        }
    }

    void clearAll() {
        queue_table_->setRowCount(0);
        tasks_.clear();
        is_processing_ = false;
    }

private slots:
    void processNextTask() {
        if (is_processing_ || tasks_.isEmpty()) {
            return;
        }
        
        ConversionTask* task = nullptr;
        for (auto& t : tasks_) {
            if (t.status == "Queued") {
                task = &t;
                break;
            }
        }
        
        if (!task) {
            is_processing_ = false;
            return;
        }
        
        is_processing_ = true;
        current_task_ = task;
        
        task->status = "Processing";
        queue_table_->setItem(task->row, 2, new QTableWidgetItem("Processing"));
        
        auto worker = new ConversionWorker(task->input_file, task->output_file, task->format);
        auto thread = new QThread;
        worker->moveToThread(thread);
        
        connect(thread, &QThread::started, worker, &ConversionWorker::startConversion);
        connect(worker, &ConversionWorker::progressUpdated, this, &ConversionQueueWidget::updateProgress);
        connect(worker, &ConversionWorker::conversionCompleted, this, &ConversionQueueWidget::taskCompleted);
        connect(worker, &ConversionWorker::conversionCompleted, thread, &QThread::quit);
        connect(thread, &QThread::finished, worker, &QObject::deleteLater);
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        
        thread->start();
    }

    void updateProgress(int percentage) {
        if (current_task_) {
            current_task_->progress = percentage;
            auto progress_bar = qobject_cast<QProgressBar*>(queue_table_->cellWidget(current_task_->row, 3));
            if (progress_bar) {
                progress_bar->setValue(percentage);
            }
        }
    }

    void taskCompleted(bool success, const QString& error) {
        if (current_task_) {
            current_task_->status = success ? "Completed" : "Failed";
            current_task_->error = error;
            
            queue_table_->setItem(current_task_->row, 2, new QTableWidgetItem(current_task_->status));
            
            if (!success) {
                auto item = queue_table_->item(current_task_->row, 2);
                item->setToolTip(error);
                item->setBackground(QBrush(QColor(255, 200, 200)));
            }
            
            current_task_ = nullptr;
        }
        
        is_processing_ = false;
        
        QTimer::singleShot(100, this, &ConversionQueueWidget::processNextTask);
    }

private:
    struct ConversionTask {
        QString input_file;
        QString output_file;
        QString format;
        QString status;
        QString error;
        int progress;
        int row;
    };

    void setupUI() {
        auto layout = new QVBoxLayout(this);
        
        auto header_layout = new QHBoxLayout;
        header_layout->addWidget(new QLabel("Conversion Queue"));
        header_layout->addStretch();
        
        auto clear_completed_btn = new QPushButton("Clear Completed");
        auto clear_all_btn = new QPushButton("Clear All");
        
        header_layout->addWidget(clear_completed_btn);
        header_layout->addWidget(clear_all_btn);
        
        queue_table_ = new QTableWidget;
        queue_table_->setColumnCount(4);
        queue_table_->setHorizontalHeaderLabels({"File", "Format", "Status", "Progress"});
        queue_table_->horizontalHeader()->setStretchLastSection(true);
        queue_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
        queue_table_->setAlternatingRowColors(true);
        
        layout->addLayout(header_layout);
        layout->addWidget(queue_table_);
        
        connect(clear_completed_btn, &QPushButton::clicked, this, &ConversionQueueWidget::clearCompleted);
        connect(clear_all_btn, &QPushButton::clicked, this, &ConversionQueueWidget::clearAll);
    }

    QTableWidget* queue_table_;
    QList<ConversionTask> tasks_;
    ConversionTask* current_task_ = nullptr;
    bool is_processing_ = false;
};

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr) : QMainWindow(parent) {
        setupUI();
        setupMenus();
        setupToolbars();
        setupStatusBar();
        connectSignals();
        loadSettings();
        
        setWindowTitle("Universal Converter - Enterprise Edition");
        setWindowIcon(QIcon(":/icons/converter.png"));
        resize(1200, 800);
        
        showMaximized();
    }

    ~MainWindow() {
        saveSettings();
    }

private slots:
    void onFilesDropped(const QStringList& files) {
        file_list_->clear();
        for (const QString& file : files) {
            auto item = new QListWidgetItem(QFileInfo(file).fileName());
            item->setData(Qt::UserRole, file);
            item->setToolTip(file);
            file_list_->addItem(item);
        }
        
        if (!files.isEmpty()) {
            output_dir_edit_->setText(QFileInfo(files.first()).absolutePath());
        }
    }

    void browseOutputDirectory() {
        QString dir = QFileDialog::getExistingDirectory(this, "Select Output Directory", output_dir_edit_->text());
        if (!dir.isEmpty()) {
            output_dir_edit_->setText(dir);
        }
    }

    void startConversion() {
        if (file_list_->count() == 0) {
            QMessageBox::warning(this, "Warning", "Please select files to convert.");
            return;
        }
        
        if (output_format_combo_->currentText().isEmpty()) {
            QMessageBox::warning(this, "Warning", "Please select output format.");
            return;
        }
        
        if (output_dir_edit_->text().isEmpty()) {
            QMessageBox::warning(this, "Warning", "Please select output directory.");
            return;
        }
        
        QString output_dir = output_dir_edit_->text();
        QString format = output_format_combo_->currentText().toLower();
        
        for (int i = 0; i < file_list_->count(); ++i) {
            auto item = file_list_->item(i);
            QString input_file = item->data(Qt::UserRole).toString();
            QString output_file = output_dir + "/" + QFileInfo(input_file).baseName() + "." + format;
            
            queue_widget_->addConversionTask(input_file, output_file, format);
        }
        
        tabs_->setCurrentIndex(1);
    }

    void showAbout() {
        QMessageBox::about(this, "About Universal Converter",
            "Universal Converter v2.0.0\n\n"
            "Enterprise-grade file conversion system\n"
            "Built with C++23, Qt6, OpenCV, FFmpeg, Boost\n\n"
            "Supports 200+ file formats across all categories:\n"
            "• Images, Videos, Audio\n"
            "• Documents, Archives, Data\n"
            "• 3D Models, Fonts, Web formats\n\n"
            "Copyright © 2024 YALOKGARua\n"
            "All rights reserved."
        );
    }

    void showSettings() {
        auto dialog = new QDialog(this);
        dialog->setWindowTitle("Settings");
        dialog->setModal(true);
        dialog->resize(500, 400);
        
        auto layout = new QVBoxLayout(dialog);
        
        auto tabs = new QTabWidget;
        
        auto general_page = new QWidget;
        auto general_layout = new QFormLayout(general_page);
        
        auto thread_count_spin = new QSpinBox;
        thread_count_spin->setRange(1, QThread::idealThreadCount() * 2);
        thread_count_spin->setValue(QThread::idealThreadCount());
        general_layout->addRow("Thread Count:", thread_count_spin);
        
        auto memory_limit_spin = new QSpinBox;
        memory_limit_spin->setRange(512, 32768);
        memory_limit_spin->setValue(2048);
        memory_limit_spin->setSuffix(" MB");
        general_layout->addRow("Memory Limit:", memory_limit_spin);
        
        auto cache_check = new QCheckBox;
        cache_check->setChecked(true);
        general_layout->addRow("Enable Caching:", cache_check);
        
        auto profile_check = new QCheckBox;
        profile_check->setChecked(false);
        general_layout->addRow("Enable Profiling:", profile_check);
        
        tabs->addTab(general_page, "General");
        
        auto ui_page = new QWidget;
        auto ui_layout = new QFormLayout(ui_page);
        
        auto theme_combo = new QComboBox;
        theme_combo->addItems({"Light", "Dark", "Auto"});
        ui_layout->addRow("Theme:", theme_combo);
        
        auto language_combo = new QComboBox;
        language_combo->addItems({"English", "Russian", "Chinese", "Japanese", "German", "French", "Spanish"});
        ui_layout->addRow("Language:", language_combo);
        
        auto notifications_check = new QCheckBox;
        notifications_check->setChecked(true);
        ui_layout->addRow("Show Notifications:", notifications_check);
        
        tabs->addTab(ui_page, "Interface");
        
        layout->addWidget(tabs);
        
        auto button_box = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        layout->addWidget(button_box);
        
        connect(button_box, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(button_box, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        
        dialog->exec();
    }

private:
    void setupUI() {
        auto central_widget = new QWidget;
        setCentralWidget(central_widget);
        
        auto main_layout = new QHBoxLayout(central_widget);
        
        auto left_panel = new QWidget;
        left_panel->setMinimumWidth(400);
        left_panel->setMaximumWidth(500);
        
        auto left_layout = new QVBoxLayout(left_panel);
        
        drop_widget_ = new FileDropWidget;
        left_layout->addWidget(drop_widget_);
        
        auto files_group = new QGroupBox("Selected Files");
        auto files_layout = new QVBoxLayout(files_group);
        
        file_list_ = new QListWidget;
        file_list_->setMaximumHeight(150);
        files_layout->addWidget(file_list_);
        
        auto file_buttons_layout = new QHBoxLayout;
        auto add_files_btn = new QPushButton("Add Files");
        auto remove_files_btn = new QPushButton("Remove");
        auto clear_files_btn = new QPushButton("Clear All");
        
        file_buttons_layout->addWidget(add_files_btn);
        file_buttons_layout->addWidget(remove_files_btn);
        file_buttons_layout->addWidget(clear_files_btn);
        files_layout->addLayout(file_buttons_layout);
        
        left_layout->addWidget(files_group);
        
        auto output_group = new QGroupBox("Output Settings");
        auto output_layout = new QFormLayout(output_group);
        
        output_format_combo_ = new QComboBox;
        output_format_combo_->addItems({
            "JPEG", "PNG", "GIF", "BMP", "TIFF", "WEBP", "HEIF", "AVIF",
            "MP4", "AVI", "MOV", "MKV", "WMV", "FLV", "WEBM",
            "MP3", "WAV", "FLAC", "OGG", "AAC", "M4A", "WMA",
            "PDF", "DOCX", "XLSX", "PPTX", "ODT", "RTF", "TXT",
            "ZIP", "RAR", "7Z", "TAR", "GZ", "BZ2",
            "JSON", "XML", "CSV", "YAML", "TOML"
        });
        output_layout->addRow("Format:", output_format_combo_);
        
        auto output_dir_layout = new QHBoxLayout;
        output_dir_edit_ = new QLineEdit;
        auto browse_btn = new QPushButton("Browse");
        output_dir_layout->addWidget(output_dir_edit_);
        output_dir_layout->addWidget(browse_btn);
        output_layout->addRow("Directory:", output_dir_layout);
        
        left_layout->addWidget(output_group);
        
        auto convert_btn = new QPushButton("Start Conversion");
        convert_btn->setMinimumHeight(40);
        convert_btn->setStyleSheet(
            "QPushButton {"
            "background-color: #4CAF50;"
            "color: white;"
            "border: none;"
            "border-radius: 5px;"
            "font-size: 14px;"
            "font-weight: bold;"
            "}"
            "QPushButton:hover {"
            "background-color: #45a049;"
            "}"
            "QPushButton:pressed {"
            "background-color: #3d8b40;"
            "}"
        );
        left_layout->addWidget(convert_btn);
        
        main_layout->addWidget(left_panel);
        
        auto splitter = new QSplitter(Qt::Horizontal);
        
        tabs_ = new QTabWidget;
        
        options_widget_ = new ConversionOptionsWidget;
        auto options_scroll = new QScrollArea;
        options_scroll->setWidget(options_widget_);
        options_scroll->setWidgetResizable(true);
        tabs_->addTab(options_scroll, "Options");
        
        queue_widget_ = new ConversionQueueWidget;
        tabs_->addTab(queue_widget_, "Queue");
        
        auto preview_widget = new QWidget;
        auto preview_layout = new QVBoxLayout(preview_widget);
        
        preview_label_ = new QLabel("Select a file to preview");
        preview_label_->setAlignment(Qt::AlignCenter);
        preview_label_->setMinimumHeight(300);
        preview_label_->setStyleSheet("border: 1px solid #ccc; background-color: #f5f5f5;");
        preview_layout->addWidget(preview_label_);
        
        tabs_->addTab(preview_widget, "Preview");
        
        auto log_widget = new QTextEdit;
        log_widget->setReadOnly(true);
        log_widget->setMaximumHeight(200);
        tabs_->addTab(log_widget, "Log");
        
        splitter->addWidget(tabs_);
        main_layout->addWidget(splitter);
        
        connect(browse_btn, &QPushButton::clicked, this, &MainWindow::browseOutputDirectory);
        connect(convert_btn, &QPushButton::clicked, this, &MainWindow::startConversion);
        connect(output_format_combo_, &QComboBox::currentTextChanged, options_widget_, &ConversionOptionsWidget::setFormat);
    }

    void setupMenus() {
        auto file_menu = menuBar()->addMenu("File");
        
        auto open_action = file_menu->addAction("Open Files");
        open_action->setShortcut(QKeySequence::Open);
        
        auto save_action = file_menu->addAction("Save Project");
        save_action->setShortcut(QKeySequence::Save);
        
        auto load_action = file_menu->addAction("Load Project");
        
        file_menu->addSeparator();
        
        auto exit_action = file_menu->addAction("Exit");
        exit_action->setShortcut(QKeySequence::Quit);
        
        auto edit_menu = menuBar()->addMenu("Edit");
        
        auto preferences_action = edit_menu->addAction("Preferences");
        preferences_action->setShortcut(QKeySequence::Preferences);
        
        auto tools_menu = menuBar()->addMenu("Tools");
        
        auto batch_action = tools_menu->addAction("Batch Converter");
        auto metadata_action = tools_menu->addAction("Metadata Editor");
        auto benchmark_action = tools_menu->addAction("Benchmark");
        
        auto help_menu = menuBar()->addMenu("Help");
        
        auto about_action = help_menu->addAction("About");
        auto manual_action = help_menu->addAction("User Manual");
        auto support_action = help_menu->addAction("Support");
        
        connect(preferences_action, &QAction::triggered, this, &MainWindow::showSettings);
        connect(about_action, &QAction::triggered, this, &MainWindow::showAbout);
        connect(exit_action, &QAction::triggered, this, &QWidget::close);
    }

    void setupToolbars() {
        auto main_toolbar = addToolBar("Main");
        
        auto open_action = main_toolbar->addAction(QIcon(":/icons/open.png"), "Open");
        auto save_action = main_toolbar->addAction(QIcon(":/icons/save.png"), "Save");
        
        main_toolbar->addSeparator();
        
        auto convert_action = main_toolbar->addAction(QIcon(":/icons/convert.png"), "Convert");
        auto stop_action = main_toolbar->addAction(QIcon(":/icons/stop.png"), "Stop");
        
        main_toolbar->addSeparator();
        
        auto settings_action = main_toolbar->addAction(QIcon(":/icons/settings.png"), "Settings");
    }

    void setupStatusBar() {
        status_label_ = new QLabel("Ready");
        statusBar()->addWidget(status_label_);
        
        progress_bar_ = new QProgressBar;
        progress_bar_->setVisible(false);
        statusBar()->addPermanentWidget(progress_bar_);
        
        memory_label_ = new QLabel("Memory: 0 MB");
        statusBar()->addPermanentWidget(memory_label_);
        
        auto timer = new QTimer(this);
        connect(timer, &QTimer::timeout, this, [this]() {
            // Update memory usage
        });
        timer->start(1000);
    }

    void connectSignals() {
        connect(drop_widget_, &FileDropWidget::filesDropped, this, &MainWindow::onFilesDropped);
    }

    void loadSettings() {
        QSettings settings;
        restoreGeometry(settings.value("geometry").toByteArray());
        restoreState(settings.value("windowState").toByteArray());
    }

    void saveSettings() {
        QSettings settings;
        settings.setValue("geometry", saveGeometry());
        settings.setValue("windowState", saveState());
    }

private:
    FileDropWidget* drop_widget_;
    QListWidget* file_list_;
    QComboBox* output_format_combo_;
    QLineEdit* output_dir_edit_;
    QTabWidget* tabs_;
    ConversionOptionsWidget* options_widget_;
    ConversionQueueWidget* queue_widget_;
    QLabel* preview_label_;
    QLabel* status_label_;
    QProgressBar* progress_bar_;
    QLabel* memory_label_;
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    
    app.setApplicationName("Universal Converter");
    app.setApplicationVersion("2.0.0");
    app.setOrganizationName("YALOKGARua");
    app.setOrganizationDomain("github.com/YALOKGARua");
    
    QPixmap splash_pixmap(":/images/splash.png");
    QSplashScreen splash(splash_pixmap);
    splash.show();
    
    splash.showMessage("Loading modules...", Qt::AlignBottom | Qt::AlignCenter, Qt::white);
    app.processEvents();
    
    QThread::msleep(1000);
    
    splash.showMessage("Initializing engines...", Qt::AlignBottom | Qt::AlignCenter, Qt::white);
    app.processEvents();
    
    QThread::msleep(1000);
    
    MainWindow window;
    splash.finish(&window);
    window.show();
    
    return app.exec();
}

#include "main_window.moc" 