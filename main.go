package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

var (
	selectedFilePath       string
	filePathLabel          *widget.Label
	keyDeal                Uint128
	selectedEncryptionMode string
	symprogressBar         *widget.ProgressBar
	asymprogressBar        *widget.ProgressBar
)
var iv = make([]byte, 16)
var benaloh = NewBenaloh(257)

func main() {
	/*
		inputFileName := "C:/Users/baran/OneDrive/Рабочий стол/Example/Test.jpg"
		outputEncryptedFileName := "C:/Users/baran/OneDrive/Рабочий стол/Example/encrypted_output.txt"
		outputDecryptedFileName := "C:/Users/baran/OneDrive/Рабочий стол/Example/decrypted_output.jpg"

		fileData, err := ioutil.ReadFile(inputFileName)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		uArray := BytesArrayToUint128Array(fileData)

		key_deal := Uint128{
			High: 0b1000111011011001101010101001100001110101111110101101000111110100,
			Low:  0b0010111110001011010111111010111000011001010101011001101101110001,
		}

		iv := make([]byte, 16)
		rand.Read(iv)

		temp1 := EncrypBlocks(uArray, key_deal, "Random delta", iv)
		temp2 := DecryptBlocks(temp1, key_deal, "Random delta", iv)

		err = ioutil.WriteFile(outputEncryptedFileName, Uint128ArrayToBytesArray(temp1), 0644)
		if err != nil {
			fmt.Println("Ошибка при записи зашифрованных данных в файл:", err)
			return
		}

		fmt.Println("Зашифрованные данные записаны в файл:", outputEncryptedFileName)

		err = ioutil.WriteFile(outputDecryptedFileName, Uint128ArrayToBytesArray(temp2), 0644)
		if err != nil {
			fmt.Println("Ошибка при записи расшифрованных данных в файл:", err)
			return
		}

		fmt.Println("Расшифрованные данные записаны в файл:", outputDecryptedFileName)
	*/
	myApp := app.New()
	myWindow := myApp.NewWindow("Шифрование/Дешифрование")

	myWindow.Resize(fyne.NewSize(600, 400))
	filePathLabel = widget.NewLabel(selectedFilePath)
	rand.Read(iv)

	symprogressBar = widget.NewProgressBar()
	symprogressBar.Resize(fyne.NewSize(200, symprogressBar.MinSize().Height))

	asymprogressBar = widget.NewProgressBar()
	asymprogressBar.Resize(fyne.NewSize(200, asymprogressBar.MinSize().Height))

	highLabel := widget.NewLabel(fmt.Sprintf("High: %d", keyDeal.High))
	lowLabel := widget.NewLabel(fmt.Sprintf("Low: %d", keyDeal.Low))
	pLabel := widget.NewLabel(fmt.Sprintf("Big Int: %s", benaloh.p.String()))
	qLabel := widget.NewLabel(fmt.Sprintf("Big Int: %s", benaloh.q.String()))

	highEntry := widget.NewEntry()
	lowEntry := widget.NewEntry()
	pEntry := widget.NewEntry()
	qEntry := widget.NewEntry()

	symmetricButton := widget.NewButton("Сгенерировать ключ симметричного алгоритма", func() {
		keyDeal = generateSymmetricKey()
		fmt.Println("Сгенерирован ключ симметричного алгоритма:", keyDeal)
		highLabel.SetText(fmt.Sprintf("High: %d", keyDeal.High))
		lowLabel.SetText(fmt.Sprintf("Low: %d", keyDeal.Low))
	})

	asymmetricButton := widget.NewButton("Сгенерировать ключ асимметричного алгоритма", func() {
		generateAsymmetricKey()
		keyAsymmetricP := benaloh.p
		keyAsymmetricQ := benaloh.q
		fmt.Println("Сгенерирован ключ асимметричного алгоритма: p =", keyAsymmetricP, "q =", keyAsymmetricQ)
		pLabel.SetText(fmt.Sprintf("Big Int P: %s", benaloh.p.String()))
		qLabel.SetText(fmt.Sprintf("Big Int Q: %s", benaloh.q.String()))
	})

	applyButton := widget.NewButton("Применить введенные значения", func() {
		applyValues(highEntry, lowEntry, pEntry, qEntry)

		p, successP := new(big.Int).SetString(pEntry.Text, 10)
		q, successQ := new(big.Int).SetString(qEntry.Text, 10)

		if (!successP && !successQ) || (successP && successQ && p.Cmp(big.NewInt(1e18)) > 0 && q.Cmp(big.NewInt(1e18)) > 0) {

			if (!successP && !successQ) || (MillerRabin(p) && MillerRabin(q)) {
				highLabel.SetText(fmt.Sprintf("High: %s", highEntry.Text))
				lowLabel.SetText(fmt.Sprintf("Low: %s", lowEntry.Text))
				pLabel.SetText(fmt.Sprintf("Big Int P: %s", pEntry.Text))
				qLabel.SetText(fmt.Sprintf("Big Int Q: %s", qEntry.Text))
			} else {
				dialog.ShowError(errors.New("Один или несколько введенных чисел не проходят тест Миллера-Рабина"), myWindow)
			}
		} else {
			dialog.ShowError(errors.New("Одно или несколько введенных чисел не находится в требуемом диапазоне"), myWindow)
		}
	})

	selectFileButton := widget.NewButton("Выбрать файл", func() {
		showFileSelectionDialog(myWindow)
	})

	selectModeButton := widget.NewButton("Выбрать режим шифрования", func() {
		showEncryptionModeDialog(myWindow)
	})

	symEncryptButton := widget.NewButton("Шифрование симметричным алгоритмом", func() {
		if selectedFilePath == "" {
			fmt.Println("Выберите файл для шифрования")
			return
		}

		fileData, err := ioutil.ReadFile(selectedFilePath)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		uArray := BytesArrayToUint128Array(fileData)

		if selectedEncryptionMode == "" {
			fmt.Println("Выберите режим шифрования")
			return
		}

		go func() {
			symprogressBar.SetValue(0)

			temp1 := EncrypBlocks(uArray, keyDeal, selectedEncryptionMode, iv)
			totalBlocks := len(uArray)

			for i := 0; i < totalBlocks; i++ {
				symprogressBar.SetValue(float64(i+1) / float64(totalBlocks))
			}

			symprogressBar.SetValue(1.0)

			outputEncryptedFileName := "encrypted_output.txt"
			err := ioutil.WriteFile(outputEncryptedFileName, Uint128ArrayToBytesArray(temp1), 0644)
			if err != nil {
				fmt.Println("Ошибка при записи зашифрованных данных в файл:", err)
				return
			}

			fmt.Println("Зашифрованные данные записаны в файл:", outputEncryptedFileName)
		}()
	})

	symDecryptButton := widget.NewButton("Дешифрование симметричным алгоритмом", func() {
		if selectedFilePath == "" {
			fmt.Println("Выберите файл для дешифрования")
			return
		}

		fileData, err := ioutil.ReadFile(selectedFilePath)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		uArray := BytesArrayToUint128Array(fileData)

		if selectedEncryptionMode == "" {
			fmt.Println("Выберите режим шифрования")
			return
		}

		// Производим дешифрацию
		go func() {
			symprogressBar.SetValue(0)

			temp1 := DecryptBlocks(uArray, keyDeal, selectedEncryptionMode, iv)
			totalBlocks := len(uArray)

			for i := 0; i < totalBlocks; i++ {
				fyne.CurrentApp().Driver().CanvasForObject(symprogressBar).Refresh(symprogressBar)
				symprogressBar.SetValue(float64(i+1) / float64(totalBlocks))
			}

			symprogressBar.SetValue(1.0)

			outputDecryptedFileName := "decrypted_output.txt"
			err := ioutil.WriteFile(outputDecryptedFileName, Uint128ArrayToBytesArray(temp1), 0644)
			if err != nil {
				fmt.Println("Ошибка при записи зашифрованных данных в файл:", err)
				return
			}

			fmt.Println("Зашифрованные данные записаны в файл:", outputDecryptedFileName)
		}()
	})

	asymEncryptButton := widget.NewButton("Шифрование асимметричным алгоритмом", func() {
		if selectedFilePath == "" {
			fmt.Println("Выберите файл для шифрования")
			return
		}

		fileData, err := ioutil.ReadFile(selectedFilePath)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		blockSize := big.NewInt(1)

		var encryptedBlocks []string

		for i := 0; i < len(fileData); i += int(blockSize.Int64()) {
			blockEnd := i + int(blockSize.Int64())
			if blockEnd > len(fileData) {
				blockEnd = len(fileData)
			}

			block := fileData[i:blockEnd]
			message := new(big.Int).SetBytes(block)

			ciphertext := benaloh.Encrypt(message)

			progressValue := float64(i) / float64(len(fileData))
			asymprogressBar.SetValue(progressValue)

			encryptedBlocks = append(encryptedBlocks, ciphertext.String())
		}

		asymprogressBar.SetValue(1.0)

		outputEncryptedFileName := "encrypted_asymmetric_output.txt"
		encryptedData := []byte(strings.Join(encryptedBlocks, "\t"))
		err = ioutil.WriteFile(outputEncryptedFileName, encryptedData, 0644)
		if err != nil {
			fmt.Println("Ошибка при записи зашифрованных данных в файл:", err)
			return
		}

		fmt.Println("Зашифрованные данные записаны в файл:", outputEncryptedFileName)
	})

	asymDecryptButton := widget.NewButton("Дешифрование асимметричным алгоритмом", func() {
		if selectedFilePath == "" {
			fmt.Println("Выберите файл для дешифрования")
			return
		}

		fileData, err := ioutil.ReadFile(selectedFilePath)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		encryptedBlocks := strings.Split(string(fileData), "\t")

		var decryptedBlocks []string

		for _, ciphertextStr := range encryptedBlocks {
			ciphertext := new(big.Int)
			ciphertext.SetString(ciphertextStr, 10)

			decryptedMessage := benaloh.Decrypt(ciphertext)

			progressValue := float64(len(decryptedBlocks)) / float64(len(encryptedBlocks))
			asymprogressBar.SetValue(progressValue)
			decryptedBlocks = append(decryptedBlocks, string(decryptedMessage.Int64()))
		}

		asymprogressBar.SetValue(1.0)

		// Создаем файл с дешифрованными данными
		outputDecryptedFileName := "decrypted_asymmetric_output.txt" // Укажите нужный путь и имя файла
		decryptedData := []byte(strings.Join(decryptedBlocks, ""))

		err = ioutil.WriteFile(outputDecryptedFileName, decryptedData, 0644)
		if err != nil {
			fmt.Println("Ошибка при записи дешифрованных данных в файл:", err)
			return
		}

		fmt.Println("Дешифрованные данные записаны в файл:", outputDecryptedFileName)
	})

	fileContainer := container.New(layout.NewVBoxLayout(),
		container.New(layout.NewCenterLayout(), filePathLabel),
		selectFileButton,
	)

	symKeyContainer := container.NewVBox(
		highLabel,
		highEntry,
		lowLabel,
		lowEntry,
		symmetricButton,
	)

	asymConteiner := container.NewVBox(
		pLabel,
		pEntry,
		qLabel,
		qEntry,
		asymmetricButton,
	)

	genKeysContainer := container.New(
		layout.NewHBoxLayout(),
		container.New(layout.NewCenterLayout(), symKeyContainer),
		container.New(layout.NewCenterLayout(), asymConteiner),
		applyButton,
	)

	selectModesContainer := container.New(
		layout.NewVBoxLayout(),
		selectModeButton,
	)

	symEncryptionContainer := container.NewVBox(
		widget.NewLabel("Симметричное шифрование"),
		symEncryptButton,
		symDecryptButton,
	)

	asymEncryptionContainer := container.NewVBox(
		widget.NewLabel("Асимметричное шифрование"),
		asymEncryptButton,
		asymDecryptButton,
	)

	symprogressBarContainer := container.New(layout.NewCenterLayout(), symprogressBar)
	symEncryptionContainer.Add(symprogressBarContainer)

	asymprogressBarContainer := container.New(layout.NewCenterLayout(), asymprogressBar)
	asymEncryptionContainer.Add(asymprogressBarContainer)

	selectModeButton.Resize(fyne.NewSize(200, selectModeButton.MinSize().Height))

	mainContainer := container.NewVBox(
		fileContainer,
		genKeysContainer,
		selectModesContainer,
		symEncryptionContainer,
		asymEncryptionContainer,
	)

	myWindow.SetContent(mainContainer)

	myWindow.ShowAndRun()
	fmt.Println("Выбранный режим шифрования:", selectedEncryptionMode)

	if selectedFilePath != "" {
		fileData, err := ioutil.ReadFile(selectedFilePath)
		if err != nil {
			fmt.Println("Ошибка при чтении файла:", err)
			return
		}

		fmt.Println("Содержимое файла:", string(fileData))
	}
}

func BigIntArrayToBytesArray(bigInts []*big.Int) []byte {
	var result []byte
	for _, bi := range bigInts {
		result = append(result, bi.Bytes()...)
	}
	return result
}

func applyValues(highEntry, lowEntry, pEntry, qEntry *widget.Entry) {
	if highEntry.Text != "" {
		keyDeal.High = parseUint64(highEntry.Text)
	}
	if lowEntry.Text != "" {
		keyDeal.Low = parseUint64(lowEntry.Text)
	}

	if pEntry.Text != "" {
		bigIntP, err := new(big.Int).SetString(pEntry.Text, 10)
		if err {
			benaloh.p.Set(bigIntP)
		}
	}

	if qEntry.Text != "" {
		bigIntQ, err := new(big.Int).SetString(qEntry.Text, 10)
		if err {
			benaloh.q.Set(bigIntQ)
		}
	}

	if highEntry.Text == "" || lowEntry.Text == "" {
		highEntry.SetText(fmt.Sprintf("%d", keyDeal.High))
		lowEntry.SetText(fmt.Sprintf("%d", keyDeal.Low))
	}

	if pEntry.Text == "" {
		pEntry.SetText(fmt.Sprintf("%s", benaloh.p.String()))
	}

	if qEntry.Text == "" {
		qEntry.SetText(fmt.Sprintf("%s", benaloh.q.String()))
	}
}

func parseUint64(s string) uint64 {
	var value uint64
	_, err := fmt.Sscanf(s, "%d", &value)
	if err != nil {
		value = 0
	}
	return value
}

// генерация асимметричного ключа
func generateAsymmetricKey() {
	benaloh.GenerateKey()
}

// генерация симметричного ключа
func generateSymmetricKey() Uint128 {
	mrand.Seed(time.Now().UnixNano())
	return Uint128{
		High: mrand.Uint64(),
		Low:  mrand.Uint64(),
	}
}

// выбор режима шифрования
func showEncryptionModeDialog(window fyne.Window) {
	encryptionModes := []string{"ECB", "CBC", "CFB", "OFB", "CTR", "Random delta"} // Ваши режимы шифрования

	selectEntry := widget.NewSelect(encryptionModes, func(selected string) {
		// Обработка выбранного режима шифрования
		fmt.Println("Выбранный режим шифрования:", selected)
		selectedEncryptionMode = selected
	})

	selectDialog := dialog.NewCustom("Выберите режим шифрования", "ОК", selectEntry, window)

	selectDialog.Show()
}

// выбор файла
func showFileSelectionDialog(window fyne.Window) {
	fileDialog := dialog.NewFileOpen(func(result fyne.URIReadCloser, err error) {
		if err == nil && result != nil {
			// Сохраняем путь к выбранному файлу
			selectedFilePath = result.URI().Path()
			fmt.Println("Выбранный файл:", selectedFilePath)

			filePathLabel.SetText(selectedFilePath)
		}
	}, window)

	fileDialog.Show()
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>BENALOH<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
type Benaloh struct {
	PublicKey   []*big.Int
	PrivateKey  []*big.Int
	p, q        *big.Int
	blockLength int
}

func NewBenaloh(blockLength int) *Benaloh {
	benaloh := &Benaloh{blockLength: blockLength}
	return benaloh
}

func (b *Benaloh) GenerateKey() {
	for {
		//генерация p и q, удовлетворяющих условию
		b.p = GenerateRandomValueWithCondition(b.blockLength)
		b.q = GenerateRandomValueWithCondition(b.blockLength)
		if b.p == nil || b.q == nil {
			continue
		}

		if new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(b.p, big.NewInt(1)), new(big.Int).Sub(b.q, big.NewInt(1))),
			big.NewInt(int64(b.blockLength))).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		tempP := new(big.Int).Div(new(big.Int).Sub(b.p, big.NewInt(1)), big.NewInt(int64(b.blockLength)))
		if new(big.Int).GCD(nil, nil, tempP, big.NewInt(int64(b.blockLength))).Cmp(big.NewInt(1)) == 0 {
			if big.NewInt(int64(b.blockLength)).Bit(0) == 0 ||
				new(big.Int).GCD(nil, nil, new(big.Int).Sub(b.q, big.NewInt(1)), big.NewInt(int64(b.blockLength))).Cmp(big.NewInt(1)) == 0 {
				break
			}
		}
	}

	//вычисление n и phi
	n := new(big.Int).Mul(b.p, b.q)
	phi := new(big.Int).Mul(new(big.Int).Sub(b.p, big.NewInt(1)), new(big.Int).Sub(b.q, big.NewInt(1)))

	//выбор y, удовлетворяющего условию
	y := GenerateYValue(phi, n, big.NewInt(int64(b.blockLength)))
	x := new(big.Int).Exp(y, new(big.Int).Div(phi, big.NewInt(int64(b.blockLength))), n)

	b.PublicKey = []*big.Int{y, big.NewInt(int64(b.blockLength)), n}
	b.PrivateKey = []*big.Int{phi, x}
}

func (b *Benaloh) Encrypt(m *big.Int) *big.Int {
	y, r, n := b.PublicKey[0], b.PublicKey[1], b.PublicKey[2]

	u, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(2)))
	if err != nil {
		return nil
	}
	u.Add(u, big.NewInt(2)) // Сдвигаем диапазон к [2, n-1]
	fmt.Println("U:", u)
	C := new(big.Int).Mul(new(big.Int).Exp(y, m, nil), new(big.Int).Exp(u, r, nil))
	C.Mod(C, n)
	return C
}

func (b *Benaloh) Decrypt(c *big.Int) *big.Int {
	phi, x := b.PrivateKey[0], b.PrivateKey[1]
	r, n := b.PublicKey[1], b.PublicKey[2]

	a := new(big.Int).Exp(c, new(big.Int).Div(phi, r), n)
	fmt.Println("A:", a)
	m := Logarithm(a, x, r, n)

	//m.Mul(m, x)
	//m.Mod(m, n)

	return m
}

func EuclidAlgorithm(a, b *big.Int) *big.Int {

	zero := big.NewInt(0)

	//сравнение b с zero
	//0 - значение равны
	for b.Cmp(zero) != 0 {
		a, b = b, new(big.Int).Mod(a, b)
	}

	return a
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>ТЕСТЫ ДЛЯ BENALOH<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
func SolovayStrassen(number *big.Int) bool {
	min := big.NewInt(2)
	max := new(big.Int).Sub(number, big.NewInt(2))

	for k := 0; k < 100; k++ {

		random_number, err := RandomIntInRange(min, max)

		if err != nil {
			fmt.Println("Ошибка при генерации случайного числа:", err)
			return false
		}

		rightDiv := expMod(random_number, new(big.Int).Sub(number, big.NewInt(1)), number)
		leftExp := new(big.Int).Exp(random_number, new(big.Int).Div(new(big.Int).Sub(number, big.NewInt(1)), big.NewInt(2)), number)

		if EuclidAlgorithm(random_number, number).Cmp(big.NewInt(1)) > 0 {
			return false
		} else if leftExp.Cmp(rightDiv) != 0 {
			return false
		}
	}
	return true
}

// тест Миллера-Pабина
func MillerRabin(number *big.Int) bool {

	if number.Bit(0) == 0 {
		return false
	}

	mrand.Seed(time.Now().UnixNano())
	t := new(big.Int).Sub(number, big.NewInt(1))
	exp := big.NewInt(0)

	for t.Bit(0) == 0 {
		t.Rsh(t, 1)
		exp.Add(exp, big.NewInt(1))
	}

	for i := 0; i < 100; i++ {
		temp := new(big.Int).Sub(number, big.NewInt(3)) //2 <= a <= number-2
		a := new(big.Int).Add(big.NewInt(2), new(big.Int).SetUint64(uint64(mrand.Intn(int(temp.Int64())))))

		x := new(big.Int).Exp(a, t, number)

		if x.Cmp(big.NewInt(1)) != 0 && x.Cmp(new(big.Int).Sub(number, big.NewInt(1))) != 0 {
			for j := big.NewInt(0); j.Cmp(new(big.Int).Sub(exp, big.NewInt(1))) != 0; j.Add(j, big.NewInt(1)) {
				x = x.Exp(x, big.NewInt(2), number)

				if x.Cmp(new(big.Int).Sub(number, big.NewInt(1))) == 0 {
					break
				}

				if x.Cmp(big.NewInt(1)) == 0 {
					return false
				}

			}
			if x.Cmp(new(big.Int).Sub(number, big.NewInt(1))) != 0 {
				return false
			}
		}
	}
	return true
}

// тест Ферма
func Fermat(number *big.Int) bool {

	if number.Bit(0) == 0 {
		return false
	}

	mrand.Seed(time.Now().UnixNano())

	for k := 0; k < 100; k++ {
		temp := new(big.Int).Sub(number, big.NewInt(3)) //2 <= a <= number-2
		a := new(big.Int).Add(big.NewInt(2), new(big.Int).SetUint64(uint64(mrand.Intn(int(temp.Int64())))))

		if a.Exp(a, new(big.Int).Sub(number, big.NewInt(1)), number).Cmp(big.NewInt(1)) != 0 {
			return false
		}
	}
	return true
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ BENALOH<<<<<<<<<<<<<<<<<<<<<<<
func RandomIntInRange(min, max *big.Int) (*big.Int, error) {
	diff := new(big.Int).Sub(max, min)
	diff.Add(diff, big.NewInt(1))

	result, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return nil, err
	}

	result.Add(result, min)
	return result, nil
}

// возведение в степень по модулю
func expMod(b, n, m *big.Int) *big.Int {
	result := big.NewInt(1)

	for n.Cmp(big.NewInt(0)) > 0 {
		if n.Bit(0) == 1 {
			result.Mul(result, b)
			result.Mod(result, m)
		}
		b.Mul(b, b)
		b.Mod(b, m)
		n.Rsh(n, 1)
	}
	return result
}

func GenerateRandomValueWithCondition(blockLength int) *big.Int {
	for {
		//value, err := RandomIntInRange(big.NewInt(10000), big.NewInt(99999))
		value, err := RandomIntInRange(big.NewInt(1000000000000000000), big.NewInt(9223372036854775807))
		if err != nil || !MillerRabin(value) {
			continue
		}
		return value
	}
}

// Функция для разложения составного числа на множители
func Factorize(n *big.Int) []*big.Int {
	factors := make([]*big.Int, 0)

	// Деление на 2 до тех пор, пока число не станет нечетным
	for new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
		factors = append(factors, big.NewInt(2))
		n.Div(n, big.NewInt(2))
	}

	// Перебор нечетных чисел в поиске простых множителей
	three := big.NewInt(3)
	for new(big.Int).Sqrt(n).Cmp(three) >= 0 {
		for new(big.Int).Mod(n, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
			factors = append(factors, new(big.Int).Set(three))
			n.Div(n, three)
		}
		three.Add(three, big.NewInt(2))
	}

	// Если n стало простым числом больше 2
	if n.Cmp(big.NewInt(2)) > 0 {
		factors = append(factors, new(big.Int).Set(n))
	}

	return factors
}

func GenerateYValue(phi, n *big.Int, r *big.Int) *big.Int {
	for {
		// Генерируем y в диапазоне [2, n-1]
		y, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(2)))
		if err != nil {
			fmt.Println("Error generating random value:", err)
			return nil
		}
		y.Add(y, big.NewInt(2)) // Сдвигаем диапазон к [2, n-1]

		if !MillerRabin(r) {
			temp := make([]*big.Int, 0)
			factor := Factorize(y)

			for _, i := range factor {
				// Вычисляем x = y^(phi/r) mod n
				exp := new(big.Int).Div(phi, r)
				x := new(big.Int).Exp(i, exp, n)

				one := big.NewInt(1)
				if x.Cmp(one) != 0 {
					temp = append(temp, i)
				} else {
					break
				}

				if len(temp) == len(factor) {
					return y
				}
			}
		} else {

			// Вычисляем x = y^(phi/r) mod n
			exp := new(big.Int).Div(phi, r)
			x := new(big.Int).Exp(y, exp, n)

			// Проверяем условие Y^(phi/r) != 1 mod n
			one := big.NewInt(1)
			if x.Cmp(one) != 0 {
				return y
			}
		}
	}
}

func Logarithm(a, x, r, n *big.Int) *big.Int {
	for m := big.NewInt(0); m.Cmp(r) < 0; m.Add(m, big.NewInt(1)) {
		if new(big.Int).Exp(x, m, n).Cmp(a) == 0 {
			return m
		}
	}
	return nil
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>DES<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
var C1 = []byte{
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
}

var D1 = []byte{
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}

var Cdi = []byte{
	13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3,
	25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39,
	50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31,
}

var cyclBitShift = []byte{
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
}

var expansionE = []byte{
	31, 0, 1, 2, 3, 4,
	3, 4, 5, 6, 7, 8,
	7, 8, 9, 10, 11, 12,
	11, 12, 13, 14, 15, 16,
	15, 16, 17, 18, 19, 20,
	19, 20, 21, 22, 23, 24,
	23, 24, 25, 26, 27, 28,
	27, 28, 29, 30, 31, 0,
}

var sBlock = [8][4][16]byte{
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

var pBlock = []byte{
	15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
	1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
}

type DES struct {
	Key uint64
}

func NewDES(key uint64) *DES {
	return &DES{
		Key: key,
	}
}

func (d *DES) Encrypt(inputBlock, key uint64) uint64 {
	left := uint32(inputBlock >> 32)
	right := uint32(inputBlock) & ((1 << 32) - 1)
	new_left, new_right := uint32(0), uint32(0)

	roundKey := d.GenerateRandKeys(key)
	for count_round := 0; count_round < 16; count_round++ {
		new_left = right
		new_right = left ^ d.InitialPermuntation(right, roundKey[count_round])
		left = new_left
		right = new_right
	}
	outBlock := uint64(new_left)<<32 | uint64(new_right)
	return outBlock
}

func (d *DES) Decrypt(inputBlock, key uint64) uint64 {
	left := uint32(inputBlock >> 32)
	right := uint32(inputBlock) & ((1 << 32) - 1)
	new_left, new_right := uint32(0), uint32(0)

	roundKey := d.GenerateRandKeys(key)
	for count_round := 15; count_round >= 0; count_round-- {
		new_right = left
		new_left = right ^ d.InitialPermuntation(left, roundKey[count_round])
		left = new_left
		right = new_right
	}
	outBlock := uint64(new_left)<<32 | uint64(new_right)
	return outBlock
}

func (d *DES) InitialPermuntation(input uint32, key uint64) uint32 {
	expanBlock := permutatin_32_48(input, expansionE)
	e_block := (reverseBits(expanBlock) >> 16) ^ key
	s_block := permuntation_s(e_block, sBlock)
	p_block := uint32(reverseBits(uint64(permutatin_32_32(s_block, pBlock))) >> 32)

	return p_block
}

func (d *DES) GenerateRandKeys(key uint64) []uint64 {
	result := make([]uint64, 0)
	permKeyC := permutatin_64_28(key, C1)
	permKeyD := permutatin_64_28(key, D1)

	for round := 0; round < 16; round++ {
		permKeyC = leftCirculShift(permKeyC, cyclBitShift[round])
		permKeyD = leftCirculShift(permKeyD, cyclBitShift[round])

		combinedKey := (uint64(permKeyC) << 28) | uint64(permKeyD)
		combinedKey = reverseBits(combinedKey)
		roundKey := reverseBits(permutatin_56_48(combinedKey, Cdi)) >> 16
		result = append(result, roundKey)

	}
	return result
}

func permutatin_64_28(input uint64, permTable []byte) uint32 {
	var result uint32
	for i := 0; i < 28; i++ {
		bitNumber := permTable[i]
		shiftedBit := (input >> bitNumber) & 1
		result = (result << 1) | uint32(shiftedBit)
	}
	return result
}

func permutatin_56_48(input uint64, permTable []byte) uint64 {
	var result uint64
	for i := 0; i < len(permTable); i++ {
		bitNumber := permTable[i]
		shiftedBit := (input >> (8 + bitNumber)) & 1
		result = (result << 1) | shiftedBit
	}
	return result
}

func permutatin_32_48(input uint32, permTable []byte) uint64 {
	var result uint64
	for i := 0; i < len(permTable); i++ {
		bitNumber := permTable[i]
		shiftedBit := uint64(input>>bitNumber) & 1
		result = (result << 1) | shiftedBit
	}
	return result
}

func permuntation_s(input uint64, sBox [8][4][16]byte) uint32 {
	var blockArray byte
	var outputArray uint32

	for i, first := 0, 0; i < 8; i, first = i+1, first+6 {
		line := byte(((input >> first) & 0x1) | (((input >> (first + 5)) & 0x1) << 1))
		column := byte(((input >> (first + 1)) & 0x1) | (((input >> (first + 2)) & 0x1) << 1) | (((input >> (first + 3)) & 0x1) << 2) | (((input >> (first + 4)) & 0x1) << 3))

		blockArray = blockSearch(i, line, column, sBox)

		for j := 0; j < 4; j++ {
			outputArray |= (uint32(blockArray>>j&1) << uint32(j+(4*i)))
		}
	}
	return outputArray
}

func permutatin_32_32(input uint32, permTable []byte) uint32 {
	var result uint32
	for i := 0; i < 32; i++ {
		bitNumber := permTable[i]
		shiftedBit := (input >> bitNumber) & 1
		result = (result << 1) | shiftedBit
	}
	return result
}

func leftCirculShift(value uint32, shift byte) uint32 {
	shift %= 28
	return (value >> shift) | (value << (28 - shift) & 0x0FFFFFFF)
}

func reverseBits(input uint64) uint64 {
	var result uint64
	for i := 0; i < 64; i++ {
		bitValue := (input >> i) & 1
		result = (result << 1) | bitValue
	}
	return result
}

func blockSearch(block int, line, column byte, sBlock [8][4][16]byte) byte {
	for i, j := 0, 0; i < 4 && j < 16; {
		if (byte(i) != line) && (byte(j) != column) {
			i++
			j++
		} else if byte(i) != line {
			i++
		} else if byte(j) != column {
			j++
		} else {
			return sBlock[block][i][j]
		}
	}
	return 0
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>DEAL<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
type Uint128 struct {
	High uint64
	Low  uint64
}

type DEAL struct {
	Key128 Uint128
	Des    *DES
}

func NewDEAL(key128 Uint128, des *DES) *DEAL {
	return &DEAL{
		Key128: key128,
		Des:    des,
	}
}

func (d *DEAL) GenerateKeys() []uint64 {
	result := make([]uint64, 0)
	firstKey := d.Des.Encrypt(d.Key128.High, d.Des.Key)
	secondKey := d.Des.Encrypt((d.Key128.Low ^ firstKey), d.Des.Key)
	thirdKey := d.Des.Encrypt((d.Key128.High ^ 0x8000000000000000 ^ secondKey), d.Des.Key)
	fourthKey := d.Des.Encrypt((d.Key128.Low ^ 0x4000000000000000 ^ thirdKey), d.Des.Key)
	fifth := d.Des.Encrypt((d.Key128.High ^ 0x2000000000000000 ^ fourthKey), d.Des.Key)
	sixth := d.Des.Encrypt((d.Key128.Low ^ 0x1000000000000000 ^ fifth), d.Des.Key)

	result = append(result, firstKey, secondKey, thirdKey, fourthKey, fifth, sixth)
	return result
}

func (d *DEAL) Encrypt(block, key Uint128) Uint128 {
	left := block.High
	right := block.Low
	new_left, new_right := uint64(0), uint64(0)

	roundKey := d.GenerateKeys()
	for i := 0; i < 6; i++ {
		new_right = left
		new_left = right ^ d.Des.Encrypt(left, roundKey[i])
		right = new_right
		left = new_left
	}
	output := Uint128{
		High: new_left,
		Low:  new_right,
	}
	return output
}

func (d *DEAL) Decrypt(block, key Uint128) Uint128 {
	left := block.High
	right := block.Low
	new_left, new_right := uint64(0), uint64(0)

	roundKey := d.GenerateKeys()
	for i := 5; i >= 0; i-- {
		new_left = right
		new_right = left ^ d.Des.Encrypt(right, roundKey[i])
		left = new_left
		right = new_right
	}
	output := Uint128{
		High: new_left,
		Low:  new_right,
	}
	return output
}

func Uint128ToBytes(u Uint128) []byte {
	bytes := make([]byte, 16)
	binary.BigEndian.PutUint64(bytes[:8], u.High)
	binary.BigEndian.PutUint64(bytes[8:], u.Low)
	return bytes
}

func BytesToUint128(bytes []byte) Uint128 {
	if len(bytes) < 16 {
		return Uint128{}
	}

	high := binary.BigEndian.Uint64(bytes[:8])
	low := binary.BigEndian.Uint64(bytes[8:])

	return Uint128{
		High: high,
		Low:  low,
	}
}

func BytesArrayToUint128Array(bytesArray []byte) []Uint128 {
	numUint128 := len(bytesArray) / 16
	uArray := make([]Uint128, numUint128)

	for i := 0; i < numUint128; i++ {
		uArray[i] = BytesToUint128(bytesArray[i*16 : (i+1)*16])
	}

	remainingBytes := len(bytesArray) % 16
	if remainingBytes > 0 {
		lastBlock := make([]byte, 16)
		copy(lastBlock, bytesArray[numUint128*16:numUint128*16+remainingBytes])
		uArray = append(uArray, BytesToUint128(lastBlock))
	}

	return uArray
}

func Uint128ArrayToBytesArray(uArray []Uint128) []byte {
	bytesArray := make([]byte, len(uArray)*16)

	for i, u := range uArray {
		uBytes := Uint128ToBytes(u)
		copy(bytesArray[i*16:(i+1)*16], uBytes)
	}

	return bytesArray
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>НАБИВКА<<<<<<<<<<<<<<<<<<<<<<<<<<<
func Pkcs7PadData(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func Pkcs7UnpadData(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>РЕЖИМЫ<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
func EncrypBlocks(dataU []Uint128, key_deal Uint128, mode string, iv []byte) []Uint128 {
	key_des := uint64(0b1111111111101110010111011100110010111011101010100001100110001111)
	des := NewDES(key_des)
	deal := NewDEAL(key_deal, des)

	arr_data := make([]byte, len(dataU)*16)
	encryptedBlocks := make([]byte, 0)

	for i, u := range dataU {
		uBytes := Uint128ToBytes(u)
		copy(arr_data[i*16:(i+1)*16], uBytes)
	}

	for i := 0; i < len(arr_data); i += 16 {
		end := i + 16
		if end > len(arr_data) {
			end = len(arr_data)
		}

		block := arr_data[i:end]

		// Обработка padding для последнего блока
		if len(block) < 16 {
			block = Pkcs7PadData(block, 16)
		}

		var encryptedBlock []byte

		switch mode {
		case "ECB":
			temp := BytesToUint128(block)
			encryptedBlock = Uint128ToBytes(deal.Encrypt(temp, key_deal))

		case "CBC":
			xorBlock := xor(block, iv)
			temp := BytesToUint128(xorBlock)
			encryptedBlock = Uint128ToBytes(deal.Encrypt(temp, key_deal))
			iv = encryptedBlock

		case "CFB":
			encryptedBlock = Uint128ToBytes(deal.Encrypt(BytesToUint128(iv), key_deal))
			encryptedBlock = xor(encryptedBlock, block)
			iv = encryptedBlock

		case "OFB":
			encryptedBlock = Uint128ToBytes(deal.Encrypt(BytesToUint128(iv), key_deal))
			iv = encryptedBlock
			encryptedBlock = xor(encryptedBlock, block)

		case "CTR":
			counterBlock := make([]byte, 16)
			binary.BigEndian.PutUint64(counterBlock, uint64(i/16))
			encryptedCounter := deal.Encrypt(BytesToUint128(counterBlock), key_deal)
			encryptedBlock = xor(Uint128ToBytes(encryptedCounter), block)

		case "Random delta":
			encryptedBlock = xor(block, iv)
		}

		encryptedBlocks = append(encryptedBlocks, encryptedBlock...)
	}

	if len(encryptedBlocks)%16 != 0 {
		return nil
	}
	numUint128 := len(encryptedBlocks) / 16
	uArray := make([]Uint128, numUint128)

	for i := 0; i < numUint128; i++ {
		uArray[i] = BytesToUint128(encryptedBlocks[i*16 : (i+1)*16])
	}

	return uArray
}

func DecryptBlocks(dataU []Uint128, key_deal Uint128, mode string, iv []byte) []Uint128 {
	key_des := uint64(0b1111111111101110010111011100110010111011101010100001100110001111)
	des := NewDES(key_des)
	deal := NewDEAL(key_deal, des)

	arr_data := make([]byte, len(dataU)*16)
	decryptedBlocks := make([]byte, 0)

	for i, u := range dataU {
		uBytes := Uint128ToBytes(u)
		copy(arr_data[i*16:(i+1)*16], uBytes)
	}

	for i := 0; i < len(arr_data); i += 16 {
		end := i + 16
		if end > len(arr_data) {
			end = len(arr_data)
		}

		block := arr_data[i:end]

		// Обработка padding для последнего блока
		if len(block) < 16 {
			block = Pkcs7PadData(block, 16)
		}

		var decryptedBlock []byte

		switch mode {
		case "ECB":
			temp := BytesToUint128(block)
			decryptedBlock = Uint128ToBytes(deal.Decrypt(temp, key_deal))
		case "CBC":
			temp := BytesToUint128(block)
			decryptedBlock = Uint128ToBytes(deal.Decrypt(temp, key_deal))
			decryptedBlock = xor(decryptedBlock, iv)
			iv = block

		case "CFB":
			temp := BytesToUint128(iv)
			decryptedBlock = Uint128ToBytes(deal.Encrypt(temp, key_deal))
			decryptedBlock = xor(decryptedBlock, block)
			iv = block

		case "OFB":
			temp := BytesToUint128(iv)
			decryptedBlock = Uint128ToBytes(deal.Encrypt(temp, key_deal))
			iv = decryptedBlock
			decryptedBlock = xor(decryptedBlock, block)

		case "CTR":
			counterBlock := make([]byte, 16)
			binary.BigEndian.PutUint64(counterBlock, uint64(i/16))
			encryptedCounter := deal.Encrypt(BytesToUint128(counterBlock), key_deal)
			decryptedBlock = xor(Uint128ToBytes(encryptedCounter), block)

		case "Random delta":
			decryptedBlock = xor(block, iv)
		}
		decryptedBlocks = append(decryptedBlocks, decryptedBlock...)

	}

	if len(decryptedBlocks)%16 != 0 {
		return nil
	}
	numUint128 := len(decryptedBlocks) / 16
	uArray := make([]Uint128, numUint128)

	for i := 0; i < numUint128; i++ {
		uArray[i] = BytesToUint128(decryptedBlocks[i*16 : (i+1)*16])
	}

	return uArray
}

func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
